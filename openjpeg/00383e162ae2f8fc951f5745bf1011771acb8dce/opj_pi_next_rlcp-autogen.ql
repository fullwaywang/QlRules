/**
 * @name openjpeg-00383e162ae2f8fc951f5745bf1011771acb8dce-opj_pi_next_rlcp
 * @id cpp/openjpeg/00383e162ae2f8fc951f5745bf1011771acb8dce/opj-pi-next-rlcp
 * @description openjpeg-00383e162ae2f8fc951f5745bf1011771acb8dce-src/lib/openjp2/pi.c-opj_pi_next_rlcp CVE-2020-27841
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpi_294, RelationalOperation target_4, NotExpr target_5) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("opj_event_msg")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="manager"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_294
		and target_0.getArgument(1).(Literal).getValue()="1"
		and target_0.getArgument(2) instanceof StringLiteral
		and target_4.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpi_294, VariableAccess target_1) {
		target_1.getTarget()=vpi_294
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_3(Parameter vpi_294, FunctionCall target_3) {
		target_3.getTarget().hasName("opj_pi_emit_error")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vpi_294
		and target_3.getArgument(1) instanceof StringLiteral
}

predicate func_4(Parameter vpi_294, RelationalOperation target_4) {
		 (target_4 instanceof GEExpr or target_4 instanceof LEExpr)
		and target_4.getLesserOperand().(PointerFieldAccess).getTarget().getName()="include_size"
		and target_4.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_294
}

predicate func_5(Parameter vpi_294, NotExpr target_5) {
		target_5.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="include"
		and target_5.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_294
}

from Function func, Parameter vpi_294, VariableAccess target_1, FunctionCall target_3, RelationalOperation target_4, NotExpr target_5
where
not func_0(vpi_294, target_4, target_5)
and func_1(vpi_294, target_1)
and func_3(vpi_294, target_3)
and func_4(vpi_294, target_4)
and func_5(vpi_294, target_5)
and vpi_294.getType().hasName("opj_pi_iterator_t *")
and vpi_294.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
