(this.webpackJsonpclient=this.webpackJsonpclient||[]).push([[0],{109:function(e,t,a){e.exports=a(136)},136:function(e,t,a){"use strict";a.r(t);var n,r=a(0),c=a.n(r),l=a(11),o=a.n(l),i=a(172),u=a(175),s=a(176),m=a(137),d=a(84),p=a.n(d),f=a(88),h=a.n(f),E=a(87),v=a.n(E),b=a(86),y=a.n(b),g=a(10),x=a(92),j=a(66),O=Object(r.createContext)(),k=function(e){var t=Object(r.useState)(!0),a=Object(g.a)(t,2),n=a[0],l=a[1],o=Object(x.a)({palette:{primary:n?{light:"#7986cb",main:"#3f51b5",dark:"#303f9f"}:{main:j.a[500],light:j.a[200],dark:j.a[800]},type:n?"light":"dark"}});Object(r.useEffect)((function(){var e=(new Date).getHours();l(!(e>=19||e<=6))}),[]);return c.a.createElement(O.Provider,{value:{theme:o,handleTheme:function(){return l(!n)},lightMode:n}},e.children)},C=Object(i.a)((function(){return{root:{display:"flex",justifyContent:"center",width:"100%"}}})),w=function(){var e=C(),t=Object(r.useContext)(O),a=t.lightMode,n=t.handleTheme,l=[c.a.createElement(p.a,null),a?c.a.createElement(y.a,{fontSize:"large"}):c.a.createElement(v.a,{fontSize:"large"}),c.a.createElement(h.a,null)];return c.a.createElement(u.a,{className:e.root},l.map((function(e,t){return c.a.createElement(s.a,{key:t,style:{justifyContent:"center"}},c.a.createElement(m.a,{onClick:1===t?n:null},e))})))},T=a(16),D=a(6),S=a(29),_=a(32),z=a.n(_),F=a(53),W=a(54),H=a.n(W),A=Object(r.createContext)(),G=function(e){var t=Object(r.useState)([]),a=Object(g.a)(t,2),n=a[0],l=a[1],o=Object(r.useState)({open:!1,message:""}),i=Object(g.a)(o,2),u=i[0],s=i[1],m=function(){var e=Object(F.a)(z.a.mark((function e(){var t,a;return z.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.prev=0,e.next=3,H.a.get("/api/tasks");case 3:t=e.sent,a=t.data,l(a),e.next=11;break;case 8:e.prev=8,e.t0=e.catch(0),console.log(e.t0.response);case 11:case"end":return e.stop()}}),e,null,[[0,8]])})));return function(){return e.apply(this,arguments)}}(),d=function(){var e=Object(F.a)(z.a.mark((function e(t){var a,r;return z.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.prev=0,e.next=3,H.a.post("/api/tasks",t);case 3:a=e.sent,r=a.data,s({open:!0,message:"Task added Successfully!"}),l([r].concat(Object(T.a)(n))),e.next=12;break;case 9:e.prev=9,e.t0=e.catch(0),console.log(e.t0.response.data);case 12:case"end":return e.stop()}}),e,null,[[0,9]])})));return function(t){return e.apply(this,arguments)}}(),p=function(){var e=Object(F.a)(z.a.mark((function e(t,a){return z.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.prev=0,e.next=3,H.a.put("/api/tasks/".concat(t),a);case 3:s({open:!0,message:"Task Updated Successfully!"}),e.next=9;break;case 6:e.prev=6,e.t0=e.catch(0),console.log(e.t0.response.data);case 9:case"end":return e.stop()}}),e,null,[[0,6]])})));return function(t,a){return e.apply(this,arguments)}}(),f=function(){var e=Object(F.a)(z.a.mark((function e(t){var a,n;return z.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.prev=0,e.next=3,H.a.delete("/api/tasks/".concat(t));case 3:a=e.sent,n=a.data,s({open:!0,message:n.message}),e.next=11;break;case 8:e.prev=8,e.t0=e.catch(0),console.log(e.t0.response.data);case 11:case"end":return e.stop()}}),e,null,[[0,8]])})));return function(t){return e.apply(this,arguments)}}();return function(){var e=new Date,t=!0,a=!1,r=void 0;try{for(var c,l=n[Symbol.iterator]();!(t=(c=l.next()).done);t=!0){var o=c.value;e.getDate()-new Date(o.expTime).getDate()>=1&&e.getHours()>=new Date(o.expTime).getHours()&&o.status&&f(o._id)}}catch(i){a=!0,r=i}finally{try{t||null==l.return||l.return()}finally{if(a)throw r}}}(),Object(r.useEffect)((function(){m()}),[]),c.a.createElement(A.Provider,{value:{tasks:n,addTask:d,feedback:u,setFeedback:s,handleTaskUpdate:function(e,t){var a=Object(T.a)(n),r=a.find((function(t){return t._id===e}));a[a.indexOf(r)]=t,p(e,t),l(a)},handleDelete:function(e){f(e);var t=n.filter((function(t){return t._id!==e}));l(t)},handleCompleted:function(e){var t=Object(T.a)(n),a=t.find((function(t){return t._id===e}));a.status=!a.status,p(e,a),l(t)}}},e.children)},P=a(68),U=a(89),B=a.n(U),I=a(90),J=a.n(I),L=a(196),M=a(181),V=a(193),N=a(183),$=a(198),q=a(184),K=a(185),Q=a(186),R=a(180),X=a(187),Y=a(195),Z=a(177),ee=a(178),te=a(179),ae=function(e){var t=e.open,a=e.handleClose,n=e.task_id,l=Object(r.useContext)(A).handleDelete;return c.a.createElement(Y.a,{open:t,onClose:a},c.a.createElement(Z.a,null,c.a.createElement(ee.a,{component:"div"},c.a.createElement(P.a,{variant:"h6",component:"p",color:"textPrimary"},"Are you sure you want to delete this task?"))),c.a.createElement(te.a,null,c.a.createElement(R.a,{onClick:a,color:"primary"},"Cancel"),c.a.createElement(R.a,{onClick:function(e){l(n),a()},variant:"contained",color:"primary",autoFocus:!0},"Confirm")))},ne=a(14),re=a(192),ce=a(65),le=function(){var e=Object(r.useContext)(A),t=e.tasks,a=e.handleCompleted,l=e.handleTaskUpdate,o=Object(r.useState)(!1),i=Object(g.a)(o,2),d=i[0],p=i[1],f=Object(r.useState)({title:"",description:"",expTime:"",status:""}),h=Object(g.a)(f,2),E=h[0],v=h[1],b=Object(r.useState)([]),y=Object(g.a)(b,2),x=y[0],j=y[1],O=Object(r.useState)(),k=Object(g.a)(O,2),C=k[0],w=k[1],_={fontStyle:"italic",textDecoration:"line-through",opacity:.5},z=function(e,t){return function(a){v(Object(S.a)({},t,Object(D.a)({},e,a.target.value)))}},F=function(e){var t=Object(T.a)(x).filter((function(t){return t!==e}));j(t)},W=new Date;return c.a.createElement(c.a.Fragment,null,c.a.createElement(u.a,null,t.map((function(e){return c.a.createElement(s.a,{key:e._id},c.a.createElement(L.a,{style:{width:"100%"}},c.a.createElement(M.a,null,x.includes(e._id)?c.a.createElement("div",{style:{flexGrow:1}},c.a.createElement(V.a,{name:"title",variant:"outlined",type:"text",size:"small",placeholder:"Add title",onChange:z("title",e),onFocus:z("title",e),defaultValue:e.title,autoFocus:!0})):c.a.createElement(P.a,{variant:"h6",style:e.status?Object(S.a)({},_,{flexGrow:1,paddingTop:7,textTransform:"capitalize"}):{flexGrow:1,paddingTop:7,textTransform:"capitalize"}},e.title),c.a.createElement(N.a,{"aria-label":"Task Status",onChange:function(t){return a(e)},control:c.a.createElement($.a,{color:"primary",checked:e.status,onChange:function(t){return a(e._id,E)}})}),c.a.createElement(m.a,{onClick:function(t){n=e._id,p(!0)}},c.a.createElement(B.a,{color:"secondary"}))),c.a.createElement(q.a,null,x.includes(e._id)?c.a.createElement(K.a,{container:!0,justify:"flex-end"},c.a.createElement(V.a,{name:"description",type:"text",variant:"outlined",size:"small",placeholder:"Description",onChange:z("description",e),fullWidth:!0,multiline:!0,rows:"4",defaultValue:e.description})):c.a.createElement(P.a,{variant:"subtitle2",color:"textSecondary",align:"center",component:"p",style:{width:"100%"}},e.description)),c.a.createElement(Q.a,null,c.a.createElement("div",{style:{marginLeft:20,flexGrow:1}},x.includes(e._id)?c.a.createElement(ne.a,{utils:ce.a},c.a.createElement(re.a,{variant:"inline",value:C,onChange:w,onBlur:function(t){return v(Object(S.a)({},e,{expTime:C}))},onError:console.log,placeholder:"Date and Time of activity"})):c.a.createElement(P.a,{variant:"caption",color:e.status?"textSecondary":"primary",component:"small",style:{fontWeight:"bolder"}},new Date(e.expTime).getDate()===W.getDate()?function(e){var t=e.toLocaleTimeString().split(":"),a=t[2].split(" ")[1];return t.pop(),"".concat(t.join(":")," ").concat(a)}(new Date(e.expTime)):new Date(e.expTime).toDateString())),x.includes(e._id)?c.a.createElement("div",{style:{marginTop:15}},c.a.createElement(R.a,{color:"primary",onClick:function(t){return F(e._id)}},"Close"),c.a.createElement(R.a,{variant:"contained",color:"primary",onClick:function(t){l(e._id,E),F(e._id),v(Object(S.a)({},E,{expTime:C}))}},"Done")):c.a.createElement(X.a,{size:"small",color:"primary",style:{margin:15},disabled:e.status,onClick:function(t){return function(e){w(e.expTime),j([].concat(Object(T.a)(x),[e._id]))}(e)}},c.a.createElement(J.a,{fontSize:"small"})))))}))),c.a.createElement(ae,{open:d,handleClose:function(){return p(!1)},task_id:n}))},oe=a(91),ie=a.n(oe),ue=a(188),se=function(e){var t=e.date,a=e.handleDateTimeChange;return c.a.createElement(ne.a,{utils:ce.a},c.a.createElement(K.a,{container:!0,justify:"space-around"},c.a.createElement(re.a,{variant:"inline",value:t,onChange:a,onError:console.log,disablePast:!0,placeholder:"Date and Time of activity",format:"dd/mm/yyyy HH:mm"})))},me=function(e){var t=e.open,a=e.handleClose,n=Object(r.useContext)(A).addTask,l=Object(r.useState)({title:"",expTime:new Date((new Date).toISOString()),description:"",status:!1}),o=Object(g.a)(l,2),i=o[0],u=o[1],s=function(e){return function(t){return u(Object(S.a)({},i,Object(D.a)({},e,t.target.value)))}};return c.a.createElement(Y.a,{open:t,onClose:a},c.a.createElement(ue.a,null,"Create a new activity"),c.a.createElement(Z.a,null,c.a.createElement(K.a,{container:!0,component:"form",spacing:2},c.a.createElement(K.a,{item:!0,xs:12},c.a.createElement(V.a,{name:"title",type:"text",variant:"outlined",size:"small",placeholder:"Activity Title",value:i.title,onChange:s("title"),fullWidth:!0})),c.a.createElement(K.a,{item:!0,xs:12},c.a.createElement(V.a,{name:"description",type:"text",variant:"outlined",size:"small",placeholder:"Description",value:i.description,onChange:s("description"),fullWidth:!0,multiline:!0,rows:"4"})),c.a.createElement(K.a,{item:!0,xs:!0},c.a.createElement(se,{date:i.expTime,handleDateTimeChange:function(e){return u(Object(S.a)({},i,{expTime:new Date(e).toUTCString()}))}})))),c.a.createElement(te.a,null,c.a.createElement(R.a,{color:"primary",onClick:a},"Cancel"),c.a.createElement(R.a,{variant:"contained",color:"primary",autoFocus:!0,onClick:function(){n(i),a()},disabled:!i.title||!i.expTime},"Done")))},de=function(){var e=Object(r.useState)(!1),t=Object(g.a)(e,2),a=t[0],n=t[1];return c.a.createElement("div",{style:{width:"100%",position:"fixed",bottom:"15%",left:"85%"}},c.a.createElement(X.a,{color:"primary",onClick:function(e){return n(!0)}},c.a.createElement(ie.a,null)),c.a.createElement(me,{open:a,handleClose:function(){return n(!1)}}))},pe=a(189),fe=a(190),he=a(191),Ee=a(197),ve=a(194),be=function(){var e=Object(r.useContext)(A),t=e.feedback,a=e.setFeedback;return c.a.createElement(Ee.a,{open:t.open,anchorOrigin:{vertical:"bottom",horizontal:"left"},autoHideDuration:3e3,onClose:function(e){return a(Object(S.a)({},t,{open:!1}))}},c.a.createElement(ve.a,{severity:"success"},t.message))},ye=function(){var e=Object(r.useContext)(O).theme;return c.a.createElement(pe.a,{theme:e},c.a.createElement(fe.a,null),c.a.createElement(w,null),c.a.createElement(he.a,{maxWidth:"md"},c.a.createElement("br",null),c.a.createElement(P.a,{variant:"h4",align:"center"},"The Todo App"),c.a.createElement("br",null),c.a.createElement(le,null)),c.a.createElement(de,null),c.a.createElement(be,null))};Boolean("localhost"===window.location.hostname||"[::1]"===window.location.hostname||window.location.hostname.match(/^127(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$/));o.a.render(c.a.createElement(k,null,c.a.createElement(G,null,c.a.createElement(ye,null))),document.getElementById("root")),"serviceWorker"in navigator&&navigator.serviceWorker.ready.then((function(e){e.unregister()})).catch((function(e){console.error(e.message)}))}},[[109,1,2]]]);
//# sourceMappingURL=main.a4fc312c.chunk.js.map