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
    var $tbl_aplist = $("#tbl_aplist");



    //Button click handlers
    $( "#scanap" ).click( function( event ) {
    	$btnscanap_load.show();
    	var jqxhr = $.get( "/", { action: "scanap"})
		  .done(function(data) {
		  	// Clear tbl_aplist, add headers
		  	$tbl_aplist.empty();
		  	var newrow = $("<tr><th>Details</th><th>Send to Track</th><th>MAC</th><th>SSID</th></tr>");
		  	newrow.appendTo($tbl_aplist);

		  	var data = $.parseJSON(data);
		  	var msg = data.msg;
		  	var status = data.status;
		  	console.log(msg);
		  	data = data.data
		  	macs = Object.keys(data)
		  	$.each(macs, function(index, mac) {
		  		var btn_send = '<button id="btn_track" class="ui-button ui-widget ui-corner-all" mac="'+mac+'" ssid="'+data[mac].ssid+'">Send</button>';
    			var btn_details = '<button id="btn_details" class="ui-button ui-widget ui-corner-all" mac="'+mac+'" ssid="'+data[mac].ssid+'">View</button>';
    			
    			newrow = $("<tr><td>"+btn_details+"</td><td>"+btn_send+"</td><td>" + mac + "</td><td>" + data[mac].ssid + "</td></tr>");
				newrow.appendTo($tbl_aplist);
			});
		  })
		  .fail(function(data) {
		    alert( "Error when scanning for APs" );
		  })
		  .always(function() {
		  	$btnscanap_load.hide();
		  })
	});

	
	$tbl_aplist.on('click', '#btn_track', function() {
    	var mac = $(this).attr("mac");
		var ssid = $(this).attr("ssid");

		$('#txt_track_mac').val(mac);
		$('#txt_track_ssid').val(ssid);

		$('#accordion').accordion('option','active',1);
	});

});

//Handler functions
