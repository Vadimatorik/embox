/**
 * @file
 * @brief Core clocking device in Cortex ARM-M
 *
 * @date 25.03.2014
 * @author Anton Kozlov
 */


#include <errno.h>
#include <hal/clock.h>
#include <hal/system.h>
#include <arm/exception.h>
#include <kernel/irq.h>
#include <kernel/time/clock_source.h>

#include <embox/unit.h>

#define CLOCK_DIVIDER 1

#define SYSTICK_IRQ 15

#include <module/embox/arch/arm/cmsis.h>

static struct clock_source this_clock_source;
static irq_return_t clock_handler(unsigned int irq_nr, void *data) {
	clock_tick_handler(data);
	return IRQ_HANDLED;
}

static int this_init(void) {
	return clock_source_register(&this_clock_source);
}

static int this_set_periodic(struct clock_source *cs) {
	int reload = SYS_CLOCK / (CLOCK_DIVIDER * 1000);

	return 0 == SysTick_Config(reload) ? 0 : -EINVAL;
}

static struct time_event_device this_event = {
	.set_periodic = this_set_periodic,
	.event_hz = 1000,
	.irq_nr = SYSTICK_IRQ,
};

#if 0
static cycle_t this_read(struct clock_source *cs) {
	return 0;
}

static struct time_counter_device this_counter = {
	.read = this_read,
	.cycles_hz = SYS_CLOCK / CLOCK_DIVIDER,
};
#endif

static struct clock_source this_clock_source = {
	.name = "system_tick",
	.event_device = &this_event,
	/*.counter_device = &this_counter,*/
};

EMBOX_UNIT_INIT(this_init);

STATIC_EXC_ATTACH(SYSTICK_IRQ, clock_handler, &this_clock_source);
