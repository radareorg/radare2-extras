/* r2w keyboard hotkeys actions */

$(document).ready(function() {
	$(".cmd").keypress(function(e) {
		if (e.keyCode == '13') {
			var val = $(this).val()
			alert ("EXECUTE COMMAND: "+val);
			$(this).val('')
			$("#log-zone").val(val+"\n"+$("#log-zone").val());
		}
	});
});
