/**
 * @name openjpeg-00383e162ae2f8fc951f5745bf1011771acb8dce-opj_pi_next_pcrl
 * @id cpp/openjpeg/00383e162ae2f8fc951f5745bf1011771acb8dce/opj-pi-next-pcrl
 * @description openjpeg-00383e162ae2f8fc951f5745bf1011771acb8dce-src/lib/openjp2/pi.c-opj_pi_next_pcrl CVE-2020-27841
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpi_472, BlockStmt target_7, RelationalOperation target_3) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="compno0"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="poc"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_472
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="numcomps"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_472
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="compno1"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="poc"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_472
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="numcomps"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_472
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen()=target_7
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpi_472, RelationalOperation target_3) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("opj_event_msg")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="manager"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_472
		and target_1.getArgument(1).(Literal).getValue()="1"
		and target_1.getArgument(2).(StringLiteral).getValue()="opj_pi_next_pcrl(): invalid compno0/compno1"
		and target_3.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vpi_472, ExprStmt target_9) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof RelationalOperation
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="manager"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_472
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vpi_472, Variable vindex_476, BlockStmt target_7, RelationalOperation target_3) {
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vindex_476
		and target_3.getLesserOperand().(PointerFieldAccess).getTarget().getName()="include_size"
		and target_3.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_472
		and target_3.getParent().(IfStmt).getThen()=target_7
}

predicate func_4(Parameter vpi_472, VariableAccess target_4) {
		target_4.getTarget()=vpi_472
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Parameter vpi_472, FunctionCall target_6) {
		target_6.getTarget().hasName("opj_pi_emit_error")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vpi_472
		and target_6.getArgument(1) instanceof StringLiteral
}

predicate func_7(BlockStmt target_7) {
		target_7.getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_7.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_9(Parameter vpi_472, Variable vindex_476, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vindex_476
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="layno"
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="step_l"
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="resno"
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="step_r"
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="compno"
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_472
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="step_c"
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_472
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="precno"
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_472
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="step_p"
		and target_9.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpi_472
}

from Function func, Parameter vpi_472, Variable vindex_476, RelationalOperation target_3, VariableAccess target_4, FunctionCall target_6, BlockStmt target_7, ExprStmt target_9
where
not func_0(vpi_472, target_7, target_3)
and not func_1(vpi_472, target_3)
and not func_2(vpi_472, target_9)
and func_3(vpi_472, vindex_476, target_7, target_3)
and func_4(vpi_472, target_4)
and func_6(vpi_472, target_6)
and func_7(target_7)
and func_9(vpi_472, vindex_476, target_9)
and vpi_472.getType().hasName("opj_pi_iterator_t *")
and vindex_476.getType().hasName("OPJ_UINT32")
and vpi_472.getParentScope+() = func
and vindex_476.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
