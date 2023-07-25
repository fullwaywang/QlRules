/**
 * @name curl-0583e87ada7a3cfb10904ae4ab61b339582c5bd3-fix_hostname
 * @id cpp/curl/0583e87ada7a3cfb10904ae4ab61b339582c5bd3/fix-hostname
 * @description curl-0583e87ada7a3cfb10904ae4ab61b339582c5bd3-lib/url.c-fix_hostname CVE-2015-3144
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlen_3617, ExprStmt target_2, ExprStmt target_3, EqualityOperation target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vlen_3617
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vhost_3615, Variable vlen_3617, ExprStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhost_3615
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_3617
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getAnOperand().(CharLiteral).getValue()="46"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vhost_3615, Variable vlen_3617, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="name"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhost_3615
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_3617
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_3(Parameter vhost_3615, Variable vlen_3617, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_3617
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strlen")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhost_3615
}

from Function func, Parameter vhost_3615, Variable vlen_3617, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vlen_3617, target_2, target_3, target_1)
and func_1(vhost_3615, vlen_3617, target_2, target_1)
and func_2(vhost_3615, vlen_3617, target_2)
and func_3(vhost_3615, vlen_3617, target_3)
and vhost_3615.getType().hasName("hostname *")
and vlen_3617.getType().hasName("size_t")
and vhost_3615.getParentScope+() = func
and vlen_3617.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
