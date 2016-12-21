window.onload=function() {
    var move=document.getElementsByTagName("body")[0];
    setInterval(function() {
        move.style.marginTop=(move.style.marginTop=="4px")?"-4px":"4px";
    }, 5);
}
