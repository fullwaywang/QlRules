/**
 * @name file-d65781527c8134a1202b2649695d48d5701ac60b-mprint
 * @id cpp/file/d65781527c8134a1202b2649695d48d5701ac60b/mprint
 * @description file-d65781527c8134a1202b2649695d48d5701ac60b-src/softmagic.c-mprint CVE-2019-8905
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(SizeofExprOperator target_0 |
		target_0.getValue()="96"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vp_538, Variable vstr_643, FunctionCall target_4, FunctionCall target_5) {
	exists(SubExpr target_1 |
		target_1.getLeftOperand().(SizeofExprOperator).getValue()="96"
		and target_1.getRightOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vstr_643
		and target_1.getRightOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="s"
		and target_1.getRightOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_538
		and target_1.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("file_printable")
		and target_1.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(2).(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="512"
		and target_1.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(2).(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vstr_643
		and target_1.getRightOperand().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getArgument(2).(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vms_530, FunctionCall target_6, ExprStmt target_7) {
	exists(ValueFieldAccess target_2 |
		target_2.getTarget().getName()="rm_len"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="search"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vms_530
		and target_6.getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Function func) {
	exists(SizeofExprOperator target_3 |
		target_3.getValue()="96"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vp_538, FunctionCall target_4) {
		target_4.getTarget().hasName("file_fmttime")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="l"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_538
		and target_4.getArgument(1).(Literal).getValue()="0"
}

predicate func_5(Variable vstr_643, FunctionCall target_5) {
		target_5.getTarget().hasName("file_printable")
		and target_5.getArgument(1).(SizeofExprOperator).getValue()="512"
		and target_5.getArgument(2).(VariableAccess).getTarget()=vstr_643
}

predicate func_6(Parameter vms_530, FunctionCall target_6) {
		target_6.getTarget().hasName("file_fmtcheck")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vms_530
		and target_6.getArgument(2) instanceof StringLiteral
		and target_6.getArgument(3) instanceof StringLiteral
		and target_6.getArgument(4) instanceof Literal
}

predicate func_7(Parameter vms_530, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="offset"
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="search"
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vms_530
}

from Function func, Variable vp_538, Variable vstr_643, Parameter vms_530, FunctionCall target_4, FunctionCall target_5, FunctionCall target_6, ExprStmt target_7
where
not func_0(func)
and not func_1(vp_538, vstr_643, target_4, target_5)
and not func_2(vms_530, target_6, target_7)
and not func_3(func)
and func_4(vp_538, target_4)
and func_5(vstr_643, target_5)
and func_6(vms_530, target_6)
and func_7(vms_530, target_7)
and vp_538.getType().hasName("VALUETYPE *")
and vstr_643.getType().hasName("char *")
and vms_530.getType().hasName("magic_set *")
and vp_538.getParentScope+() = func
and vstr_643.getParentScope+() = func
and vms_530.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
