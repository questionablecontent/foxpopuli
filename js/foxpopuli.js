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

    

    //Scan APs
    var $btnscanap_load = $("#scanap_load").hide();
    var $span_scanap_load_msg = $("#scanap_load_msg");
    var $tbl_aplist = $("#tbl_aplist");

    //Scan Interfaces
    var $btn_scaninterfaces_load = $("#scaninterfaces_load").hide();
    var $span_scanintrfaces_load_msg = $('#scaninterfaces_load_msg')
    var $tbl_interfaces = $("#tbl_interfaces")


    //Button click handlers
    $("#stoptrackap").prop("disabled",true);

    $( "#scanap" ).click( function( event ) {
    	$("#scanap").prop("disabled",true);
    	$btnscanap_load.show();
    	$span_scanap_load_msg.text("scanning...");
    	$span_scanap_load_msg.show();
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
			var apcount = macs.length;
			$span_scanap_load_msg.text("found " + apcount + " APs");
		  })
		  .fail(function(data) {
		    alert( "Error when scanning for APs" );
		  })
		  .always(function() {
		  	$btnscanap_load.hide();
		  	$("#scanap").prop("disabled",false);
		  })
	});

	$( "#scaninterfaces" ).click( function( event ) {
    	$("#scaninterfaces").prop("disabled",true);
    	$btn_scaninterfaces_load.show();
    	$span_scanintrfaces_load_msg.text("refreshing...");
    	$span_scanintrfaces_load_msg.show();
    	var jqxhr = $.get( "/", { action: "getdevices"})
		  .done(function(data) {
		  	// Clear tbl_interfaces, add headers
		  	$tbl_interfaces.empty();
		  	var newrow = $("<tr><th>Details</th><th>Enable Monitor</th><th>Disable Monitor</th><th>Name</th></tr>");
		  	newrow.appendTo($tbl_interfaces);

		  	var data = $.parseJSON(data);
		  	var msg = data.msg;
		  	var status = data.status;
		  	console.log(msg);
		  	data = data.data
		  	macs = Object.keys(data)
		  	$.each(macs, function(index, mac) {
		  		var btn_send = '<button id="btn_details" class="ui-button ui-widget ui-corner-all" mac="'+mac+'" ssid="'+data[mac].ssid+'">Send</button>';
    			var btn_details = '<button id="btn_details" class="ui-button ui-widget ui-corner-all" mac="'+mac+'" ssid="'+data[mac].ssid+'">View</button>';
    			
    			newrow = $("<tr><td>"+btn_details+"</td><td>"+btn_send+"</td><td>" + mac + "</td><td>" + data[mac].ssid + "</td></tr>");
				newrow.appendTo($tbl_aplist);
			});
			var apcount = macs.length;
			$span_scanap_load_msg.text("found " + apcount + " APs");
		  })
		  .fail(function(data) {
		    alert( "Error when scanning for APs" );
		  })
		  .always(function() {
		  	$btnscanap_load.hide();
		  	$("#scanap").prop("disabled",false);
		  })
	});

	
	$tbl_aplist.on('click', '#btn_track', function() {
    	var mac = $(this).attr("mac");
		var ssid = $(this).attr("ssid");

		$('#txt_track_mac').val(mac);
		$('#txt_track_ssid').val(ssid);

		$('#accordion').accordion('option','active',1);
	});


	$( "#cleartrackap" ).click( function(event) {
		$('#txt_track_mac').val("");
		$('#txt_track_ssid').val("");
	});


	$( "#trackap" ).click( function( event ) {
		$("#trackap").prop("disabled",true);
		$("#stoptrackap").prop("disabled",false);
		var ssid = $('#txt_track_ssid').val();
		var mac = $('#txt_track_mac').val();
		var jqxhr = $.get( "/", { action: "hunt", mac: mac, ssid: ssid})
		  .done(function(data) {
		  	alert("hunting");
		  })
		  .fail(function(data) {
		    alert( "Error when hunting for AP" );
		  })
		  .always(function() {
		  	$("#trackap").prop("disabled",false);
		  })
	});

	$( "#stoptrackap" ).click( function( event ) {
		var jqxhr = $.get( "/", { action: "stophunt"})
		  .done(function(data) {
		  	alert("stopped")
		  })
		  .fail(function(data) {
		    alert( "Error when stopping the hunt for AP" );
		  })
		  .always(function() {
		  	$("#trackap").prop("disabled",false);
		  })
	});


});

//Handler functions
