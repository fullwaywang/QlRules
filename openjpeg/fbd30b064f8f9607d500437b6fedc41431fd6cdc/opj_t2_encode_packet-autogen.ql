/**
 * @name openjpeg-fbd30b064f8f9607d500437b6fedc41431fd6cdc-opj_t2_encode_packet
 * @id cpp/openjpeg/fbd30b064f8f9607d500437b6fedc41431fd6cdc/opj-t2-encode-packet
 * @description openjpeg-fbd30b064f8f9607d500437b6fedc41431fd6cdc-src/lib/openjp2/t2.c-opj_t2_encode_packet CVE-2020-27842
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_manager_672, Variable vprecno_679, Variable vres_687, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, RelationalOperation target_4, ExprStmt target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vprecno_679
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="pw"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_687
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="ph"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_687
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_672
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="opj_t2_encode_packet(): accessing precno=%u >= %u\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vprecno_679
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="pw"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_687
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="ph"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_687
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_4.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_manager_672, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_672
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="opj_t2_encode_packet(): only %u bytes remaining in output buffer. %u needed.\n"
		and target_1.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="6"
}

predicate func_2(Parameter vp_manager_672, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_manager_672
		and target_2.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="opj_t2_encode_packet(): only %u bytes remaining in output buffer. %u needed.\n"
		and target_2.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="2"
}

predicate func_3(Variable vprecno_679, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="precincts"
		and target_3.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vprecno_679
}

predicate func_4(Variable vres_687, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="numbands"
		and target_4.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_687
}

predicate func_5(Variable vres_687, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="bands"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vres_687
}

from Function func, Parameter vp_manager_672, Variable vprecno_679, Variable vres_687, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, RelationalOperation target_4, ExprStmt target_5
where
not func_0(vp_manager_672, vprecno_679, vres_687, target_1, target_2, target_3, target_4, target_5)
and func_1(vp_manager_672, target_1)
and func_2(vp_manager_672, target_2)
and func_3(vprecno_679, target_3)
and func_4(vres_687, target_4)
and func_5(vres_687, target_5)
and vp_manager_672.getType().hasName("opj_event_mgr_t *")
and vprecno_679.getType().hasName("OPJ_UINT32")
and vres_687.getType().hasName("opj_tcd_resolution_t *")
and vp_manager_672.getParentScope+() = func
and vprecno_679.getParentScope+() = func
and vres_687.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
