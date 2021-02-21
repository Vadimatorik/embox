/**
 * @author  Vadim Deryabkin
 * @date    21.02.2021
 */

#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <util/math.h>
#include <util/log.h>

#include <drivers/flash/flash.h>

struct flash_at45_priv {
	struct spi_device *spi;
};

uint8_t *trash_data = (uint8_t*)OPTION_GET(NUMBER,trash_data_address);

#define PIN_SPI_CS_ACTIVE 0

int spi_trans_cmd (struct spi_device *spi, uint8_t *cmd, uint32_t cmd_len, uint8_t *rx, uint32_t answer_len) {
	int rv = EIO;
	gpio_set(OPTION_GET(NUMBER,port_cs), OPTION_GET(NUMBER,pin_cs), PIN_SPI_CS_ACTIVE);

	do {
		rv = spi_transfer(spi, cmd, cmd, cmd_len);

		if (rv != 0) {
			break;
		}

		rv = spi_transfer(spi, trash_data, rx, answer_len);
	} while(0);

	gpio_set(OPTION_GET(NUMBER,port_cs), OPTION_GET(NUMBER,pin_cs), !PIN_SPI_CS_ACTIVE);
	return rv;
}

static int flash_erase_block(struct flash_dev *dev, uint32_t block) {
	int ret;
	uint32_t page_err;
	FLASH_EraseInitTypeDef erase_struct;

	assert(block < STM32_FLASH_SECTORS_COUNT);
	assert(dev->num_block_infos == 1);

	/* block is relative to flash beginning whith not
	 * the actual ROM start address. So calculate the new sector
	 * in terms of ROM start address. */
	block += stm32_flash_first_sector;
	log_debug("Erase global block %d\n", block);

	stm32_fill_flash_erase_struct(&erase_struct, block);

	HAL_FLASH_Unlock();
	ret = HAL_FLASHEx_Erase(&erase_struct, &page_err);
	HAL_FLASH_Lock();
	if (ret != HAL_OK) {
		log_error("0x%x", block);
	}

	return ret;
}

static int flash_read(struct flash_dev *dev, uint32_t base, void *data, size_t len) {
	dev->
	return 0;
}

static int flash_program(struct flash_dev *dev, uint32_t base, const void *data, size_t len) {
	int i;
	uint32_t dest;
	uint32_t *data32;
	int err = -1;

	if (!stm32_flash_check_word_aligned(base, len)
			|| ((uintptr_t) data & 0x3) != 0) {
		err = -EINVAL;
		goto err_exit;
	}

	if (!stm32_flash_check_range(dev, base, len)) {
		err = -EFBIG;
		goto err_exit;
	}

	/* Copy by word */
	dest = STM32_FLASH_START + base;
	data32 = (uint32_t *) data;

	HAL_FLASH_Unlock();
	for (i = 0; i < len / 4; i++) {
		if (HAL_OK != HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, dest, data32[i])) {
			HAL_FLASH_Lock();
			err = -EBUSY;
			goto err_exit;
		}
		dest += 4;
	}
	HAL_FLASH_Lock();
	return 0;
err_exit:
	log_error("base=0x08%x,data=%p,len=0x%x", base, data, len);
	return err;
}

static int stm32_flash_copy(struct flash_dev *dev, uint32_t base_dst,
				uint32_t base_src, size_t len) {
	return flash_program(dev, base_dst,
		(void *) STM32_FLASH_START + base_src, len);
}

static const struct flash_dev_drv at45db641e_drv = {
	.flash_read = flash_read,
	.flash_erase_block = flash_erase_block,
	.flash_program = flash_program,
	.flash_copy = flash_copy,
};

static int at45db641e_init(void *arg) {
	struct flash_dev *flash = NULL;

	gpio_setup_mode(OPTION_GET(NUMBER,port_cs), OPTION_GET(NUMBER,pin_cs), GPIO_MODE_OUTPUT);

	flash = flash_create("at45db641e", OPTION_GET(NUMBER,flash_size));
	if (flash == NULL) {
		log_error("Failed to create flash device!");
		return -1;
	}

	flash->drv = &at45db641e_drv;
	flash->size = OPTION_GET(NUMBER,flash_size);
	flash->num_block_infos = 1;
	flash->block_info[0] = (flash_block_info_t) {
		.block_size = OPTION_GET(NUMBER,block_size)),
		.blocks = OPTION_GET(NUMBER,flash_size)) / OPTION_GET(NUMBER,block_size))
	};

	struct flash_at45_priv *priv;
	priv = malloc(sizeof(struct flash_at45_priv));
	if (priv == NULL) {
		err = -ENOMEM;
		goto out_free_flash;
	}

	flash->privdata = priv;

	priv->spi = spi_dev_by_id(OPTION_GET(NUMBER,spi_id));

	return 0;

out_free_flash:
	flash_delete(flash);

	log_error("Failed to create flash emulator error=%d", err);
	return err;
}

FLASH_DEV_DEF("at45db641e", &at45db641e_drv, at45db641e_init);
