import cpp

predicate func_0(Parameter vsockindex, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(VariableAccess).getTarget()=vsockindex
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

predicate func_1(Parameter vconn) {
	exists(ValueFieldAccess target_1 |
		target_1.getTarget().getName()="proxytype"
		and target_1.getType().hasName("curl_proxytype")
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="http_proxy"
		and target_1.getQualifier().(PointerFieldAccess).getType().hasName("proxy_info")
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn)
}

predicate func_2(Parameter vconn) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="bits"
		and target_2.getType().hasName("ConnectBits")
		and target_2.getQualifier().(VariableAccess).getTarget()=vconn)
}

predicate func_3(Function func) {
	exists(VariableAccess target_3 |
		target_3.getParent().(ArrayExpr).getArrayBase() instanceof ValueFieldAccess
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter vsockindex, Function func) {
	exists(DeclStmt target_4 |
		target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("const bool")
		and target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(LogicalAndExpr).getType().hasName("int")
		and target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(LogicalAndExpr).getLeftOperand().(EQExpr).getLeftOperand() instanceof ValueFieldAccess
		and target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="proxy_ssl_connected"
		and target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(LogicalAndExpr).getRightOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vsockindex
		and target_4.getEnclosingFunction() = func
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

from Function func, Parameter vsockindex, Parameter vconn
where
not func_0(vsockindex, func)
and func_1(vconn)
and func_2(vconn)
and func_3(func)
and func_4(vsockindex, func)
and vsockindex.getType().hasName("int")
and vconn.getType().hasName("connectdata *")
and vsockindex.getParentScope+() = func
and vconn.getParentScope+() = func
select func, vsockindex, vconn
