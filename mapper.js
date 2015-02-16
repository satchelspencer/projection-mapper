(function($){
	/* LU solver appropriated from http://www.numericjs.com/*/
	function LU(r,o){o=o||!1;var f,n,e,t,u,L,U,a,l,v=Math.abs,s=r.length,c=s-1,h=new Array(s);for(o||(r=r),e=0;s>e;++e){for(U=e,L=r[e],l=v(L[e]),n=e+1;s>n;++n)t=v(r[n][e]),t>l&&(l=t,U=n);for(h[e]=U,U!=e&&(r[e]=r[U],r[U]=L,L=r[e]),u=L[e],f=e+1;s>f;++f)r[f][e]/=u;for(f=e+1;s>f;++f){for(a=r[f],n=e+1;c>n;++n)a[n]-=a[e]*L[n],++n,a[n]-=a[e]*L[n];n===c&&(a[n]-=a[e]*L[n])}}return{LU:r,P:h}}function LUsolve(r,o){var f,n,e,t,u,L=r.LU,U=L.length,a=o,l=r.P;for(f=U-1;-1!==f;--f)a[f]=o[f];for(f=0;U>f;++f)for(e=l[f],l[f]!==f&&(u=a[f],a[f]=a[e],a[e]=u),t=L[f],n=0;f>n;++n)a[f]-=a[n]*t[n];for(f=U-1;f>=0;--f){for(t=L[f],n=f+1;U>n;++n)a[f]-=a[n]*t[n];a[f]/=t[f]}return a}function solve(r,o,f){return LUsolve(LU(r,f),o)}
	
	$.fn.projectionMap = function(coords){
		var w = this.width();
		var h = this.height();
		var init = [[0,0],[w,0],[w,h],[0,h]];
		var A = coords.map(function(out, i){
			var c = init[Math.floor(i/2)];
			return (i%2==0?[c[0],c[1],1,0,0,0]:[0,0,0,c[0],c[1],1]).concat(-c[0]*coords[i],-c[1]*coords[i]);
		});
		var x = solve(A, coords);
		var t = [x[0],x[3],0,x[6],x[1],x[4],0,x[7],0,0,1,0,x[2],x[5],0,1];
		this.css({'transform' : 'matrix3d('+t.join(',')+')'});
	}
}(jQuery));