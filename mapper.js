(function($){
	/* LU solver appropriated from http://www.numericjs.com/*/
	function LU(r,o){o=o||!1;var f,n,e,t,u,L,U,a,l,v=Math.abs,s=r.length,c=s-1,h=new Array(s);for(o||(r=r),e=0;s>e;++e){for(U=e,L=r[e],l=v(L[e]),n=e+1;s>n;++n)t=v(r[n][e]),t>l&&(l=t,U=n);for(h[e]=U,U!=e&&(r[e]=r[U],r[U]=L,L=r[e]),u=L[e],f=e+1;s>f;++f)r[f][e]/=u;for(f=e+1;s>f;++f){for(a=r[f],n=e+1;c>n;++n)a[n]-=a[e]*L[n],++n,a[n]-=a[e]*L[n];n===c&&(a[n]-=a[e]*L[n])}}return{LU:r,P:h}}function LUsolve(r,o){var f,n,e,t,u,L=r.LU,U=L.length,a=o,l=r.P;for(f=U-1;-1!==f;--f)a[f]=o[f];for(f=0;U>f;++f)for(e=l[f],l[f]!==f&&(u=a[f],a[f]=a[e],a[e]=u),t=L[f],n=0;f>n;++n)a[f]-=a[n]*t[n];for(f=U-1;f>=0;--f){for(t=L[f],n=f+1;U>n;++n)a[f]-=a[n]*t[n];a[f]/=t[f]}return a}function solve(r,o,f){return LUsolve(LU(r,f),o)}
	function dup(obj){return JSON.parse(JSON.stringify(obj))};
	$.fn.projectionMap = function(coords, or){
		coords = dup(coords);
		or = dup(or);
		var A = coords.map(function(out, i){
			var xi = i%2==0?or[i]:or[i-1];
			var yi = i%2==0?or[i+1]:or[i];
			return (i%2==0?[xi,yi,1,0,0,0]:[0,0,0,xi,yi,1]).concat(-xi*coords[i],-yi*coords[i]);
		});
		var x = solve(A, coords);
		var t = [x[0],x[3],0,x[6],x[1],x[4],0,x[7],0,0,1,0,x[2],x[5],0,1];
		$(this).css({'transform' : 'matrix3d('+t.join(',')+')'});
	}
	$.fn.projectionMapGui = function(){
		var container = $(this);
		var prev = window.localStorage['pmap']?JSON.parse(window.localStorage['pmap']):false;
		var top = container.offset().top;
		var left = container.offset().left;
		var origin = [left, top, this.width()+left, top, left, this.height()+top, this.width()+left, this.height()+top];
		if(prev){
			container.projectionMap(prev.coords, prev.origin);
			origin = prev.origin;	
		}
		var coo = dup(origin);
		var v = ['top', 'bottom'];
		var h = ['left', 'right'];
		var index = 0;
		for(var i in v) for(var j in h){
			var css = {
				position : 'absolute',
				width : '10%',
				height : '10%',
				cursor : 'move'
			};
			css[v[i]] = 0;
			css[h[j]] = 0;
			container.append(getHandle(index++));
		}
		function getHandle(index){
			return $('<div>').css(css).mousedown(function(){	
				$(window).on('mousemove', function(e){
					coo[index*2] = e.pageX;
					coo[(index*2)+1] = e.pageY;
					window.localStorage['pmap'] = JSON.stringify({
						coords : coo,
						origin : origin
					});
					container.projectionMap(coo, origin);
				});
				$('body').css({'cursor' : 'none'});
				$(window).on('mouseup', function(){
					$(window).off('mousemove mouseup');
					$('body').css({'cursor' : 'default'});
				});
			});
		}
		
	}
}(jQuery));