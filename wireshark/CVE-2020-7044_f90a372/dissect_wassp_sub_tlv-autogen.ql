/**
 * @name wireshark-f90a3720b73ca140403315126e2a478c4f70ca03-dissect_wassp_sub_tlv
 * @id cpp/wireshark/f90a3720b73ca140403315126e2a478c4f70ca03/dissect-wassp-sub-tlv
 * @description wireshark-f90a3720b73ca140403315126e2a478c4f70ca03-epan/dissectors/packet-wassp.c-dissect_wassp_sub_tlv CVE-2020-7044
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Variable vtlv_type_4747, Variable vtmp_decr_4749, BlockStmt target_6, ExprStmt target_7, ExprStmt target_8, PointerDereferenceExpr target_9, ExprStmt target_10) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vtlv_type_4747
		and target_2.getLesserOperand().(PointerFieldAccess).getTarget().getName()="max_entry"
		and target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtmp_decr_4749
		and target_2.getParent().(IfStmt).getThen()=target_6
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getLocation())
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_3(Variable vtlv_type_4747, Variable vtmp_decr_4749, BlockStmt target_6, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="max_entry"
		and target_3.getQualifier().(VariableAccess).getTarget()=vtmp_decr_4749
		and target_3.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vtlv_type_4747
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_6
}

*/
/*predicate func_4(Variable vtlv_type_4747, Variable vtmp_decr_4749, BlockStmt target_6, VariableAccess target_4) {
		target_4.getTarget()=vtlv_type_4747
		and target_4.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="max_entry"
		and target_4.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtmp_decr_4749
		and target_4.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_6
}

*/
predicate func_5(Variable vtlv_type_4747, Variable vtmp_decr_4749, BlockStmt target_6, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vtlv_type_4747
		and target_5.getLesserOperand().(PointerFieldAccess).getTarget().getName()="max_entry"
		and target_5.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtmp_decr_4749
		and target_5.getParent().(IfStmt).getThen()=target_6
}

predicate func_6(Variable vtlv_type_4747, BlockStmt target_6) {
		target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_uint_format_value")
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="4"
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vtlv_type_4747
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="Unknow Wassp TLV (%d)"
		and target_6.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vtlv_type_4747
}

predicate func_7(Variable vtlv_type_4747, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtlv_type_4747
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tvb_get_ntohs")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="0"
}

predicate func_8(Variable vtlv_type_4747, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_uint_format_value")
		and target_8.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="4"
		and target_8.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vtlv_type_4747
		and target_8.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="Unknow Wassp TLV (%d)"
		and target_8.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vtlv_type_4747
}

predicate func_9(Variable vtmp_decr_4749, PointerDereferenceExpr target_9) {
		target_9.getOperand().(PointerFieldAccess).getTarget().getName()="ett_num"
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtmp_decr_4749
}

predicate func_10(Variable vtlv_type_4747, Variable vtmp_decr_4749, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("wassp_match_strval")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtmp_decr_4749
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtlv_type_4747
}

from Function func, Variable vtlv_type_4747, Variable vtmp_decr_4749, RelationalOperation target_5, BlockStmt target_6, ExprStmt target_7, ExprStmt target_8, PointerDereferenceExpr target_9, ExprStmt target_10
where
not func_2(vtlv_type_4747, vtmp_decr_4749, target_6, target_7, target_8, target_9, target_10)
and func_5(vtlv_type_4747, vtmp_decr_4749, target_6, target_5)
and func_6(vtlv_type_4747, target_6)
and func_7(vtlv_type_4747, target_7)
and func_8(vtlv_type_4747, target_8)
and func_9(vtmp_decr_4749, target_9)
and func_10(vtlv_type_4747, vtmp_decr_4749, target_10)
and vtlv_type_4747.getType().hasName("guint16")
and vtmp_decr_4749.getType().hasName("WASSP_SUBTLV_DECODER_INFO_t *")
and vtlv_type_4747.getParentScope+() = func
and vtmp_decr_4749.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
