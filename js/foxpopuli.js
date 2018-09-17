//Main
$( document ).ready(function() {
	/*$( "#btnTest" ).click(function() {
  		$.get( "/", { action: "test" }, function( data ) {
  			$("#taDisplay").html(data);
		});
	});*/

	// Accordion setup
	var icons = {
		header: "ui-icon-signal-diag",
      	activeHeader: "ui-icon-circle-arrow-s"
    };
    
    $( "#accordion" ).accordion({
      icons: icons,
      heightStyle: "content"
    });

    

    //Elements
    var $btnscanap_load = $("#scanap_load").hide();
    var $olaplist = $("#aplist");



    //Button click handlers
    $( "#scanap" ).click( function( event ) {
    	$btnscanap_load.show()
    	var jqxhr = $.get( "/", { action: "scanap"})
		  .done(function(data) {
		  	// Clear aplist
		  	$olaplist.empty();

		  	var data = $.parseJSON(data);
		  	var msg = data.msg;
		  	var status = data.status;
		  	console.log(msg);
		  	data = data.data
		  	macs = Object.keys(data)
		  	$.each(macs, function(index, mac) {
    			var newitem = $('<li></li>').addClass('ui-widget-content');
				newitem.text('MAC: ' + mac + ' SSID: ' + data[mac].ssid); //this is the value of the input
				newitem.attr('id', mac); //use attr instead of setAttribute    
				newitem.appendTo($olaplist);
			});
			$olaplist.selectable();
		  })
		  .fail(function(data) {
		    alert( "Error when scanning for APs" );
		  })
		  .always(function() {
		  	$btnscanap_load.hide()
		  })
	});

});

//Handler functions
