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

    //Button click handlers
    $("#stoptrackap").prop("disabled",true);

    $( "#scanap" ).click( function( event ) {
    	$("#scanap").prop("disabled",true);
    	$btnscanap_load.show();
    	$span_scanap_load_msg.text("scanning...");
    	$span_scanap_load_msg.show();
    	var jqxhr = $.get( "/", { action: "scanap", interface:$('#ifacelist').val()})
		  .done(function(data) {
		  	// Clear tbl_aplist, add headers
		  	$tbl_aplist.empty();
		  	var newrow = $("<tr><th>&nbsp;</th><th>Interface</th><thPhysical Device No.</th></tr>");
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

	//Interfaces Start
    var $btn_scaninterfaces_load = $("#scaninterfaces_load").hide();
    var $span_scaninterfaces_load_msg = $('#scaninterfaces_load_msg')
    var $tbl_interfaces = $("#tbl_interfaces")

	$( "#scaninterfaces" ).click( function( event ) {
    	$("#scaninterfaces").prop("disabled",true);
    	$btn_scaninterfaces_load.show();
    	$span_scaninterfaces_load_msg.text("refreshing interfaces...");
    	$span_scaninterfaces_load_msg.show();
    	var jqxhr = $.get( "/", { action: "getinterfaces"})
		  .done(function(data) {
		  	// Clear tbl_interfaces, add headers
		  	$tbl_interfaces.empty();
		  	var newrow = $("<tr><th>&nbsp;</th><th>Interface</th><th>Device No.</th><th>Mode</th></tr>");
		  	newrow.appendTo($tbl_interfaces);

		  	var data = $.parseJSON(data);
		  	var msg = data.msg;
		  	var status = data.status;
		  	console.log(msg);
		  	interfaces = data.data
		  	$.each(interfaces, function(index, iface) {
		  		var btn_toggle = "";
		  		if (iface['type'] == 'monitor') {
		  			btn_toggle = '<button id="btn_disable_monitor" class="ui-button ui-widget ui-corner-all" iface="'+iface['interface']+'">Disable MM</button>';
		  		}
		  		else if (iface['type'] == 'managed') {
		  			btn_toggle = '<button id="btn_enable_monitor" class="ui-button ui-widget ui-corner-all" iface="'+iface['interface']+'">Enable MM</button>';
		  		}
		  		else {
		  			btn_toggle = '&nbsp;';
		  		}
		  		
    			newrow = $("<tr><td>"+btn_toggle+"</td><td>"+iface['interface']+"</td><td>" + iface['wiphy'] + "</td><td>" + iface['type'] + "</td></tr>");
				newrow.appendTo($tbl_interfaces);
			});

		  	// Populate ifacelist select
		  	var jqxhr2 = $.get( "/", { action: "getmonitorinterfaces"})
		  		.done(function(data) {
		  			$('#ifacelist').empty();
		  			var data = $.parseJSON(data);
		  			var msg = data.msg;
		  			var status = data.status;
		  			console.log(msg);
		  			mmifaces = data.data;
		  			$.each(mmifaces, function(index, iface) {
		  				$('#ifacelist').append(new Option(iface,iface));
		  			});
		  		})

		  })
		  .fail(function(data) {
		    alert( "Error when refreshing interface list" );
		  })
		  .always(function() {
		  	$btn_scaninterfaces_load.hide();
		  	$("#scaninterfaces").prop("disabled",false);
		  	$span_scaninterfaces_load_msg.text("");
		  })
	});
	
	$tbl_interfaces.on('click', '#btn_enable_monitor', function() {
		var iface = $(this).attr("iface");
		var jqxhr = $.get( "/", { action: "enablemonitormode", interface: iface})
		  .done(function(data) {
		  	console.log(data);
		  })
		  .fail(function(data) {
		    console.log(data);
		  })
		  .always(function() {
		  	$( "#scaninterfaces" ).click();
		  })
	})

	$tbl_interfaces.on('click', '#btn_disable_monitor', function() {
		var iface = $(this).attr("iface");
		var jqxhr = $.get( "/", { action: "disablemonitormode", interface: iface})
		  .done(function(data) {
		  	console.log(data);
		  })
		  .fail(function(data) {
		    console.log(data);
		  })
		  .always(function() {
		  	$( "#scaninterfaces" ).click();
		  })
	})

	// Interfaces End

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
