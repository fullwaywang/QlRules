/**
 * @name memcached-554b56687a19300a75ec24184746b5512580c819-get_conn_text
 * @id cpp/memcached/554b56687a19300a75ec24184746b5512580c819-get-conn-text
 * @description memcached-554b56687a19300a75ec24184746b5512580c819-get_conn_text CVE-2019-15026
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofExprOperator target_0) {
		target_0.getValue()="4096"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="1"
		and not target_1.getValue()="0"
		and target_1.getParent().(SubExpr).getParent().(ArrayExpr).getArrayOffset() instanceof SubExpr
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getType().hasName("size_t")
		and target_2.getRValue().(SizeofExprOperator).getValue()="108"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vsock_addr_3461, ExprStmt target_11) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="sun_path"
		and target_3.getQualifier().(VariableAccess).getTarget()=vsock_addr_3461
		and target_11.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(VariableAccess target_12, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="4096"
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getValue()="4095"
		and target_4.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_12
		and target_4.getEnclosingFunction() = func)
}

predicate func_6(Variable vaddr_text_3462, VariableAccess target_12, SubExpr target_9) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vaddr_text_3462
		and target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("size_t")
		and target_6.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_6.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_12)
}

predicate func_9(Parameter vsock_addr_3461, Variable vaddr_text_3462, SubExpr target_9) {
		target_9.getValue()="4095"
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("strncpy")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vaddr_text_3462
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="sun_path"
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsock_addr_3461
}

predicate func_10(Variable vaddr_text_3462, SubExpr target_9, SubExpr target_10) {
		target_10.getValue()="4095"
		and target_10.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vaddr_text_3462
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
}

predicate func_11(Parameter vsock_addr_3461, Variable vaddr_text_3462, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("strncpy")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vaddr_text_3462
		and target_11.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="sun_path"
		and target_11.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsock_addr_3461
		and target_11.getExpr().(FunctionCall).getArgument(2) instanceof SubExpr
}

predicate func_12(Parameter vaf_3460, VariableAccess target_12) {
		target_12.getTarget()=vaf_3460
}

from Function func, Parameter vaf_3460, Parameter vsock_addr_3461, Variable vaddr_text_3462, SizeofExprOperator target_0, Literal target_1, SubExpr target_9, SubExpr target_10, ExprStmt target_11, VariableAccess target_12
where
func_0(func, target_0)
and func_1(func, target_1)
and not func_2(func)
and not func_3(vsock_addr_3461, target_11)
and not func_4(target_12, func)
and not func_6(vaddr_text_3462, target_12, target_9)
and func_9(vsock_addr_3461, vaddr_text_3462, target_9)
and func_10(vaddr_text_3462, target_9, target_10)
and func_11(vsock_addr_3461, vaddr_text_3462, target_11)
and func_12(vaf_3460, target_12)
and vaf_3460.getType().hasName("const int")
and vsock_addr_3461.getType().hasName("sockaddr *")
and vaddr_text_3462.getType().hasName("char[4096]")
and vaf_3460.getParentScope+() = func
and vsock_addr_3461.getParentScope+() = func
and vaddr_text_3462.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()