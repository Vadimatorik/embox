'use strict';

angular.module("HttpAdmin", ['ngRoute', 'ui.bootstrap'])
.controller("NavBarCtrl", ['$scope', '$location', function($scope, $location) {
    $scope.isActive = function(id) {
        return $location.path().indexOf('/' + id) == 0;
    };
}])
.controller("InterfacesAdminCtrl", ['$scope', '$http', function($scope, $http) {
    $scope.interfaces = [];

    $http.get('cgi-bin/http_admin_backend').success(function (data) {
        $scope.interfaces = data;
    });

    $scope.update = function(iface) {
        var post_data = {
            'action' : 'iface_update',
            'data' : iface
        };

        $http.post('cgi-bin/http_admin_backend', post_data);
    };
}])
.controller("DateCtrl", ['$scope', '$http', function($scope, $http) {
    $scope.date = null;

    $scope.save = function() {
        //$http.get('cgi-bin/cgi_cmd_wrapper?c=flash_settings&a=store&a=led').success(function (data) {
        //   alert('Led configuration saved!');
        //});
    };

    $scope.update = function() {
        $http.get('cgi-bin/cgi_cmd_wrapper?c=date').then(function (r) {
            var data = r.data;
            $scope.date = data;
            //alert($scope.dates);
        });
    };

    $scope.update();
}])
.config(['$routeProvider', function($routeProvider) {
    $routeProvider.
    when('/interfaces', {
        templateUrl: 'partials/interfaces.html',
    }).
    when('/date', {
        templateUrl: 'partials/date.html',
    }).
    otherwise({
        redirectTo: '/interfaces'
    });
}]);

// vim: sw=4 sts=4 expandtab
