//Main
$( document ).ready(function() {
	$( "#btnTest" ).click(function() {
  		$.get( "/", { action: "test" }, function( data ) {
  			$("#taDisplay").html(data);
		});
	});
});

//Handler functions
