/**
 * @name curl-b09c8ee15771c614c4bf3ddac893cdb12187c844-Curl_ssl_getsessionid
 * @id cpp/curl/b09c8ee15771c614c4bf3ddac893cdb12187c844/Curl-ssl-getsessionid
 * @description curl-b09c8ee15771c614c4bf3ddac893cdb12187c844-Curl_ssl_getsessionid CVE-2021-22890
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsockindex_372, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(VariableAccess).getTarget()=vsockindex_372
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vconn_369) {
	exists(ValueFieldAccess target_1 |
		target_1.getTarget().getName()="proxytype"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="http_proxy"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_369)
}

predicate func_2(Parameter vconn_369) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="bits"
		and target_2.getQualifier().(VariableAccess).getTarget()=vconn_369)
}

predicate func_4(Parameter vsockindex_372, Function func) {
	exists(DeclStmt target_4 |
		target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof ValueFieldAccess
		and target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="proxy_ssl_connected"
		and target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vsockindex_372
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

from Function func, Parameter vsockindex_372, Parameter vconn_369
where
not func_0(vsockindex_372, func)
and func_1(vconn_369)
and func_2(vconn_369)
and func_4(vsockindex_372, func)
and vsockindex_372.getType().hasName("int")
and vconn_369.getType().hasName("connectdata *")
and vsockindex_372.getParentScope+() = func
and vconn_369.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
