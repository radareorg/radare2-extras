var $background = "#101010";
var $hilight = "#999999";

$(document).ready(function() 
{
   $("#jsCall_interp").click(
    function ()
    {
      $("#panel-code").html(propOffset);
    }

  );
  $.get("/q/dbg.py?q=get&off=esp",
      runUi);
});

function loadhex(str) {
  $.get("/q/dbg.py?q=get&off="+str,
    function (off) 
    {
        $("#panel-stack").html('');
        $.ajax(
        {url:'/q/dbg?q=stack&off=' + off, 
         success:function(data) {
        $("#panel-stack").append(data)}});
       });
  };


function runUi(dbgOffset) {
/*
    $.ajax({
         type: "POST",
         url: "/q/flags",
         data: "id=33&name=name",
         success: function(msg){
                     alert( "Data Saved: " + msg );
                  }
    });
*/
  propOffset = dbgOffset; /* global variable */
  $("#panel-stack").scroll(function () 
  { 
    var actualp = document.getElementById("panel-stack").scrollHeight;
    var actual = $("#panel-stack").scrollTop();
    var total = $("#panel-stack");

    if (actualp - actual < 120) /* load on bottom */
    {
      dbgOffset = parseInt(dbgOffset)+256;
      propOffset = dbgOffset;
      $.ajax({url:'/q/dbg?q=stack&off=' + dbgOffset, 
          success:function(data) {$("#panel-stack").append(data)}
      });
    }
    if ((actual < 300) && (actual > 10))
    {  
      dbgOffset = parseInt(dbgOffset)-256;
      propOffset = dbgOffset;
      $.ajax({
         url:'/q/dbg?q=stack', 
         success:function(data) { $("#panel-stack").prepend(data); }
      });
    }
  });
      
	$("#panel-stack").change(function() {
		$.ajax({
			url: '/q/dbg?q=stack',
			success: function(data) {
				$('#panel-stack').html(data)
			}
		});
	});
	$("#panel-stack").change();

	$("#panel-regs").change(function() {
		$.ajax({
			url: '/q/dbg?q=regs',
			success: function(data) {
				$('#panel-regs').html(data)
			}
		});
	});
	$("#panel-regs").change();

	$("#panel-code").change(function() {
		$.ajax({
			url: '/q/dbg?q=code',
			success: function(data) {
				$('#panel-code').html(data)
			}
		});
	});
	$("#panel-code").change();

	function update_all() {
		$("#panel-regs").change();
		$("#panel-code").change();
		$("#panel-stack").change();
	}

	$("#panel-option").change(function() {
		var me=$('#panel-option');
		$.ajax({
			url: '/q/test?q='+me.val(),
			success: function(data) {
				$('#panel-data').html(data)
			}
		});
	});

	$("#dbg-step").click (function() {
		$.ajax({
			url: '/q/dbg?q=step',
			success: function(data) {
				update_all();
			}
		});
	});

	$("#toggle-popup").click (function() {
		var foo = $("#panel-popup");
		if (foo.css ('height') == 'auto') {
			$("#bg").show();
			foo.show ();
		} else {
			$("#bg").hide();
			foo.hide ('slow');
		}
	});
/* TODO */
	$("#toggle-bytes").click (function() {
		var foo = $("#panel-bytes");
		if (foo.css ('height') == 'auto') {
			$("#panel-bytes2").hide();
			foo.show();
		} else {
			$("#panel-bytes2").show();
			foo.hide();
		}
	});
	$("#toggle-panel").click (function() {
		var foo = $("#panel");
		if (foo.css ('width') == 'auto')
			foo.show ();
		else foo.hide ();
	});
	$("#toggle-cmdlog").click (function() {
		var foo = $("#cmdlog");
		if (foo.css ('width') == 'auto')
			foo.show ();
		else foo.hide ();
	});
	//$("#popup").hide (); //click ();
	$("#cmdlog").hide (); //click ();
	$("#toggle-hex").click (function() {
		var foo = $("#panel-stack");
		if (foo.css ('width') == 'auto')
			foo.show ();
		else foo.hide ();
	});
 
	/* Allows to edit the content of divid by inputing the new value at editableid
	 * until it loses focus */
	function toggle_editable(div) {
		var currentval = $(div).html();
		var id = $(div).get(0).id;
		$(div).html("<input id=\""+id+"\" type=\"text\" value=\""+
			currentval+"\" style=\"background:red\"/>");
	}

	function toggle_uneditable(div) {
		var currentval = $(div + ":input").val();
		$(div).html(currentval);
	}

	/* line */
	$(".line").mouseover(function() {
		$(this).css('backgroundColor', $hilight);
		$(this).css('color', "#000000");
	});

	$(".line").mouseout(function() {
		$(this).css('backgroundColor', $background);
		$(this).css('color', "#ffffff");
	});

	$(".line").click(function() {
		$(this).css('border', "1px dashed");
	});

	$(".line").dblclick(function() {
		$(this).css('border', "1px solid");
		$(this).css('backgroundColor', "red");
	});

	$(".line").mouseleave(function() {
		$(this).css('border', "0");
	});

	/* editable */
	$(".editable").dblclick(function() {
		//        toggle_editable($(this));
		$(this).get(0).contentEditable = true;
	});

	$(".editable").mouseleave(function() {
		$(this).get(0).contentEditable = false;
	});
};
