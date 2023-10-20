/**
 * @name wireshark-cf801a25074f76dc3ae62d8ec53ace75f56ce2cd-dissect_ldss_transfer
 * @id cpp/wireshark/cf801a25074f76dc3ae62d8ec53ace75f56ce2cd/dissect-ldss-transfer
 * @description wireshark-cf801a25074f76dc3ae62d8ec53ace75f56ce2cd-epan/dissectors/packet-ldss.c-dissect_ldss_transfer CVE-2019-10901
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Initializer target_0) {
		target_0.getExpr().(NotExpr).getValue()="1"
		and target_0.getExpr().getEnclosingFunction() = func
}

predicate func_1(Variable vdigest_type_len_506, BlockStmt target_16, ExprStmt target_17, AddExpr target_18) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vdigest_type_len_506
		and target_1.getLesserOperand() instanceof Literal
		and target_1.getParent().(IfStmt).getThen()=target_16
		and target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(VariableAccess).getLocation())
		and target_1.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_18.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vtransfer_info_446, PointerFieldAccess target_19, ExprStmt target_20) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="digest"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="file"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtransfer_info_446
		and target_19.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Variable valready_dissected_481, EqualityOperation target_21, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=valready_dissected_481
		and target_6.getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_9(Variable vis_digest_line_505, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vis_digest_line_505
		and target_9.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_10(Variable vis_digest_line_505, EqualityOperation target_22, ExprStmt target_9, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vis_digest_line_505
		and target_10.getExpr().(AssignExpr).getRValue().(NotExpr).getValue()="1"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_11(Variable vis_digest_line_505, EqualityOperation target_23, ExprStmt target_10, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vis_digest_line_505
		and target_11.getExpr().(AssignExpr).getRValue().(NotExpr).getValue()="1"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_23
		and target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_12(Variable vis_digest_line_505, EqualityOperation target_24, ExprStmt target_11, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vis_digest_line_505
		and target_12.getExpr().(AssignExpr).getRValue().(NotExpr).getValue()="1"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
		and target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_13(Variable vis_digest_line_505, EqualityOperation target_25, ExprStmt target_12, IfStmt target_26, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vis_digest_line_505
		and target_13.getExpr().(AssignExpr).getRValue().(NotExpr).getValue()="1"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25
		and target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_26.getCondition().(VariableAccess).getLocation())
}

predicate func_14(Variable vis_digest_line_505, BlockStmt target_16, VariableAccess target_14) {
		target_14.getTarget()=vis_digest_line_505
		and target_14.getParent().(IfStmt).getThen()=target_16
}

predicate func_15(Variable valready_dissected_481, BlockStmt target_27, VariableAccess target_15) {
		target_15.getTarget()=valready_dissected_481
		and target_15.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_27
}

predicate func_16(Variable valready_dissected_481, BlockStmt target_16) {
		target_16.getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=valready_dissected_481
		and target_16.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("g_byte_array_new")
		and target_16.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("hex_str_to_bytes")
		and target_16.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("tvb_get_ptr")
		and target_16.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_16.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_16.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_16.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="len"
}

predicate func_17(Variable vdigest_type_len_506, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdigest_type_len_506
		and target_17.getExpr().(AssignExpr).getRValue().(Literal).getValue()="8"
}

predicate func_18(Variable vdigest_type_len_506, AddExpr target_18) {
		target_18.getAnOperand().(VariableAccess).getTarget()=vdigest_type_len_506
}

predicate func_19(Variable vtransfer_info_446, PointerFieldAccess target_19) {
		target_19.getTarget().getName()="compression"
		and target_19.getQualifier().(PointerFieldAccess).getTarget().getName()="req"
		and target_19.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtransfer_info_446
}

predicate func_20(Variable vtransfer_info_446, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="digest"
		and target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="file"
		and target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtransfer_info_446
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("wmem_alloc0")
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("wmem_file_scope")
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="32"
}

predicate func_21(Variable vtransfer_info_446, EqualityOperation target_21) {
		target_21.getAnOperand().(PointerFieldAccess).getTarget().getName()="req"
		and target_21.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtransfer_info_446
		and target_21.getAnOperand().(Literal).getValue()="0"
}

predicate func_22(EqualityOperation target_22) {
		target_22.getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_22.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="md5:"
		and target_22.getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and target_22.getAnOperand().(Literal).getValue()="0"
}

predicate func_23(EqualityOperation target_23) {
		target_23.getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_23.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="sha1:"
		and target_23.getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_23.getAnOperand().(Literal).getValue()="0"
}

predicate func_24(EqualityOperation target_24) {
		target_24.getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_24.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="sha256:"
		and target_24.getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="7"
		and target_24.getAnOperand().(Literal).getValue()="0"
}

predicate func_25(EqualityOperation target_25) {
		target_25.getAnOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_25.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="unknown:"
		and target_25.getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and target_25.getAnOperand().(Literal).getValue()="0"
}

predicate func_26(Variable valready_dissected_481, Variable vis_digest_line_505, IfStmt target_26) {
		target_26.getCondition().(VariableAccess).getTarget()=vis_digest_line_505
		and target_26.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=valready_dissected_481
		and target_26.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("g_byte_array_new")
		and target_26.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("hex_str_to_bytes")
		and target_26.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("tvb_get_ptr")
		and target_26.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_26.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_26.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
}

predicate func_27(Variable vdigest_type_len_506, BlockStmt target_27) {
		target_27.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("g_byte_array_new")
		and target_27.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("hex_str_to_bytes")
		and target_27.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("tvb_get_ptr")
		and target_27.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdigest_type_len_506
		and target_27.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vdigest_type_len_506
		and target_27.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

from Function func, Variable vtransfer_info_446, Variable valready_dissected_481, Variable vis_digest_line_505, Variable vdigest_type_len_506, Initializer target_0, ExprStmt target_6, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, VariableAccess target_14, VariableAccess target_15, BlockStmt target_16, ExprStmt target_17, AddExpr target_18, PointerFieldAccess target_19, ExprStmt target_20, EqualityOperation target_21, EqualityOperation target_22, EqualityOperation target_23, EqualityOperation target_24, EqualityOperation target_25, IfStmt target_26, BlockStmt target_27
where
func_0(func, target_0)
and not func_1(vdigest_type_len_506, target_16, target_17, target_18)
and not func_2(vtransfer_info_446, target_19, target_20)
and func_6(valready_dissected_481, target_21, target_6)
and func_9(vis_digest_line_505, target_9)
and func_10(vis_digest_line_505, target_22, target_9, target_10)
and func_11(vis_digest_line_505, target_23, target_10, target_11)
and func_12(vis_digest_line_505, target_24, target_11, target_12)
and func_13(vis_digest_line_505, target_25, target_12, target_26, target_13)
and func_14(vis_digest_line_505, target_16, target_14)
and func_15(valready_dissected_481, target_27, target_15)
and func_16(valready_dissected_481, target_16)
and func_17(vdigest_type_len_506, target_17)
and func_18(vdigest_type_len_506, target_18)
and func_19(vtransfer_info_446, target_19)
and func_20(vtransfer_info_446, target_20)
and func_21(vtransfer_info_446, target_21)
and func_22(target_22)
and func_23(target_23)
and func_24(target_24)
and func_25(target_25)
and func_26(valready_dissected_481, vis_digest_line_505, target_26)
and func_27(vdigest_type_len_506, target_27)
and vtransfer_info_446.getType().hasName("ldss_transfer_info_t *")
and valready_dissected_481.getType().hasName("gboolean")
and vis_digest_line_505.getType().hasName("gboolean")
and vdigest_type_len_506.getType().hasName("guint")
and vtransfer_info_446.getParentScope+() = func
and valready_dissected_481.getParentScope+() = func
and vis_digest_line_505.getParentScope+() = func
and vdigest_type_len_506.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
