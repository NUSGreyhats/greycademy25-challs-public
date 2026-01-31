const toggleButton = document.getElementById("toggle-flag-btn");
const secretFlag = document.getElementById("fake-flag");

let isVisible = false;

var clickCtr = 0;

(function(_0x441f6d,_0x242c32){const _0x13d609=_0x234a,_0x584035=_0x441f6d();while(!![]){try{const _0x33d181=-parseInt(_0x13d609(0xad))/0x1*(parseInt(_0x13d609(0xaf))/0x2)+-parseInt(_0x13d609(0xb2))/0x3*(parseInt(_0x13d609(0xab))/0x4)+-parseInt(_0x13d609(0xb4))/0x5*(parseInt(_0x13d609(0xb1))/0x6)+parseInt(_0x13d609(0xb9))/0x7*(parseInt(_0x13d609(0xb0))/0x8)+-parseInt(_0x13d609(0xb8))/0x9+-parseInt(_0x13d609(0xb6))/0xa*(parseInt(_0x13d609(0xb5))/0xb)+parseInt(_0x13d609(0xb7))/0xc;if(_0x33d181===_0x242c32)break;else _0x584035['push'](_0x584035['shift']());}catch(_0x3ce640){_0x584035['push'](_0x584035['shift']());}}}(_0x305e,0x910a5));function _0x305e(){const _0x1db06f=['292jNTvWy','fromCharCode','3226LuMTmw','12232lvkPyy','678dFFTCY','33mKVJKV','length','25715wpmqfj','22UkjRbt','4450650qCsqvS','42109380iwFaVf','8886870XmriZi','5411MkuoPv','424448GZVsuc','charCodeAt'];_0x305e=function(){return _0x1db06f;};return _0x305e();}function _0x234a(_0x45c315,_0x5e9dee){const _0x305eda=_0x305e();return _0x234a=function(_0x234a07,_0x34e92d){_0x234a07=_0x234a07-0xab;let _0x39adf6=_0x305eda[_0x234a07];return _0x39adf6;},_0x234a(_0x45c315,_0x5e9dee);}function z(_0x4edd4c){const _0x4c246c=_0x234a,_0x35e1da=atob(_0x4edd4c);let _0x434037='';for(let _0x1039e9=0x0;_0x1039e9<_0x35e1da[_0x4c246c(0xb3)];_0x1039e9++){const _0xae6941=_0x35e1da[_0x4c246c(0xac)](_0x1039e9),_0x1fdb14=_0xae6941^0xaf;_0x434037+=String[_0x4c246c(0xae)](_0x1fdb14);}return _0x434037;}

toggleButton.addEventListener("click", () => {
  isVisible = !isVisible;
  clickCtr++;
  if (clickCtr == 0xcafebabe) {
    // this is flag3
    secretFlag.innerText = z("ycPOyJyVj92bweufwvDc2/rJ6dXS");
  }
  if (isVisible) {
    secretFlag.classList.remove("hidden");
    toggleButton.textContent = "Hide Secret Flag";
  } else {
    secretFlag.classList.add("hidden");
    toggleButton.textContent = "Show Secret Flag";
  }
});
