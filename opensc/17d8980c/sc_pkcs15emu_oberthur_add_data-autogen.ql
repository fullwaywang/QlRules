/**
 * @name opensc-17d8980c-sc_pkcs15emu_oberthur_add_data
 * @id cpp/opensc/17d8980c/sc-pkcs15emu-oberthur-add-data
 * @description opensc-17d8980c-src/libopensc/pkcs15-oberthur.c-sc_pkcs15emu_oberthur_add_data CVE-2021-42781
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinfo_len_865, Variable voffs_865, BlockStmt target_8) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=voffs_865
		and target_0.getAnOperand().(Literal).getValue()="2"
		and target_0.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=voffs_865
		and target_0.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vinfo_len_865
		and target_0.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_8)
}

predicate func_1(Variable vinfo_len_865, Variable vlabel_len_865, Variable voffs_865, BlockStmt target_8, RelationalOperation target_9, RelationalOperation target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffs_865
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlabel_len_865
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vinfo_len_865
		and target_1.getParent().(IfStmt).getThen()=target_8
		and target_9.getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(VariableAccess).getLocation())
		and target_1.getLesserOperand().(VariableAccess).getLocation().isBefore(target_10.getLesserOperand().(VariableAccess).getLocation())
		and target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_13.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vctx_860, Variable v__FUNCTION__, RelationalOperation target_10, ExprStmt target_14, ExprStmt target_15) {
	exists(DoStmt target_2 |
		target_2.getCondition() instanceof Literal
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sc_do_log_color")
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_860
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=v__FUNCTION__
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="%s: %d (%s)\n"
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(StringLiteral).getValue()="Invalid length of 'label' received"
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(8).(VariableAccess).getType().hasName("int")
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(9).(FunctionCall).getTarget().hasName("sc_strerror")
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getType().hasName("int")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Variable vinfo_blob_864, Variable vinfo_len_865, Variable voffs_865, Variable v_ret_911, ExprStmt target_16, ExprStmt target_17, RelationalOperation target_10, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffs_865
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vinfo_len_865
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfo_blob_864
		and target_3.getThen().(BlockStmt).getStmt(1).(DoStmt).getCondition() instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=v_ret_911
		and target_3.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(29)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(29).getFollowingStmt()=target_3)
		and target_16.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_10.getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable vinfo_blob_864, ExprStmt target_18, ExprStmt target_6, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfo_blob_864
		and (func.getEntryPoint().(BlockStmt).getStmt(40)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(40).getFollowingStmt()=target_4)
		and target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_5(Variable vinfo_len_865, Variable voffs_865, BlockStmt target_19, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=voffs_865
		and target_5.getLesserOperand().(VariableAccess).getTarget()=vinfo_len_865
		and target_5.getParent().(IfStmt).getThen()=target_19
}

predicate func_6(Variable vinfo_blob_864, Function func, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfo_blob_864
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Variable vinfo_len_865, Variable voffs_865, BlockStmt target_8, VariableAccess target_7) {
		target_7.getTarget()=voffs_865
		and target_7.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vinfo_len_865
		and target_7.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_8
}

predicate func_8(Variable vinfo_blob_864, Variable v_ret_911, BlockStmt target_8) {
		target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfo_blob_864
		and target_8.getStmt(1).(DoStmt).getCondition() instanceof Literal
		and target_8.getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=v_ret_911
		and target_8.getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_8.getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sc_do_log_color")
		and target_8.getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getTarget()=v_ret_911
}

predicate func_9(Variable vinfo_len_865, Variable voffs_865, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getGreaterOperand().(VariableAccess).getTarget()=voffs_865
		and target_9.getLesserOperand().(VariableAccess).getTarget()=vinfo_len_865
}

predicate func_10(Variable vinfo_len_865, Variable voffs_865, RelationalOperation target_10) {
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getGreaterOperand().(VariableAccess).getTarget()=voffs_865
		and target_10.getLesserOperand().(VariableAccess).getTarget()=vinfo_len_865
}

predicate func_11(Variable vlabel_len_865, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlabel_len_865
		and target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getValue()="254"
}

predicate func_12(Variable vlabel_len_865, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_12.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="label"
		and target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlabel_len_865
}

predicate func_13(Variable voffs_865, ExprStmt target_13) {
		target_13.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffs_865
		and target_13.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="2"
}

predicate func_14(Variable vctx_860, Variable v__FUNCTION__, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("sc_do_log_color")
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_860
		and target_14.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_14.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_14.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=v__FUNCTION__
		and target_14.getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_14.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="%s: %d (%s)\n"
		and target_14.getExpr().(FunctionCall).getArgument(7).(StringLiteral).getValue()="Failed to add data: no 'application'"
		and target_14.getExpr().(FunctionCall).getArgument(9).(FunctionCall).getTarget().hasName("sc_strerror")
}

predicate func_15(Variable vctx_860, Variable v__FUNCTION__, Variable v_ret_911, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("sc_do_log_color")
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_860
		and target_15.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_15.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_15.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=v__FUNCTION__
		and target_15.getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_15.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="%s: %d (%s)\n"
		and target_15.getExpr().(FunctionCall).getArgument(7).(StringLiteral).getValue()="Failed to add data: no 'OID'"
		and target_15.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=v_ret_911
		and target_15.getExpr().(FunctionCall).getArgument(9).(FunctionCall).getTarget().hasName("sc_strerror")
		and target_15.getExpr().(FunctionCall).getArgument(9).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v_ret_911
}

predicate func_16(Variable vinfo_blob_864, Variable voffs_865, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vinfo_blob_864
		and target_16.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffs_865
		and target_16.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_16.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vinfo_blob_864
		and target_16.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffs_865
		and target_16.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(HexLiteral).getValue()="256"
}

predicate func_17(Variable vinfo_blob_864, Variable voffs_865, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vinfo_blob_864
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffs_865
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vinfo_blob_864
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffs_865
		and target_17.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(HexLiteral).getValue()="256"
}

predicate func_18(Variable vinfo_blob_864, ExprStmt target_18) {
		target_18.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfo_blob_864
}

predicate func_19(Variable vinfo_blob_864, BlockStmt target_19) {
		target_19.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_19.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfo_blob_864
		and target_19.getStmt(1).(DoStmt).getCondition() instanceof Literal
		and target_19.getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_19.getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sc_do_log_color")
}

from Function func, Variable vctx_860, Variable vinfo_blob_864, Variable vinfo_len_865, Variable vlabel_len_865, Variable voffs_865, Variable v__FUNCTION__, Variable v_ret_911, RelationalOperation target_5, ExprStmt target_6, VariableAccess target_7, BlockStmt target_8, RelationalOperation target_9, RelationalOperation target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18, BlockStmt target_19
where
not func_0(vinfo_len_865, voffs_865, target_8)
and not func_1(vinfo_len_865, vlabel_len_865, voffs_865, target_8, target_9, target_10, target_11, target_12, target_13)
and not func_2(vctx_860, v__FUNCTION__, target_10, target_14, target_15)
and not func_3(vinfo_blob_864, vinfo_len_865, voffs_865, v_ret_911, target_16, target_17, target_10, func)
and not func_4(vinfo_blob_864, target_18, target_6, func)
and func_5(vinfo_len_865, voffs_865, target_19, target_5)
and func_6(vinfo_blob_864, func, target_6)
and func_7(vinfo_len_865, voffs_865, target_8, target_7)
and func_8(vinfo_blob_864, v_ret_911, target_8)
and func_9(vinfo_len_865, voffs_865, target_9)
and func_10(vinfo_len_865, voffs_865, target_10)
and func_11(vlabel_len_865, target_11)
and func_12(vlabel_len_865, target_12)
and func_13(voffs_865, target_13)
and func_14(vctx_860, v__FUNCTION__, target_14)
and func_15(vctx_860, v__FUNCTION__, v_ret_911, target_15)
and func_16(vinfo_blob_864, voffs_865, target_16)
and func_17(vinfo_blob_864, voffs_865, target_17)
and func_18(vinfo_blob_864, target_18)
and func_19(vinfo_blob_864, target_19)
and vctx_860.getType().hasName("sc_context *")
and vinfo_blob_864.getType().hasName("unsigned char *")
and vinfo_len_865.getType().hasName("size_t")
and vlabel_len_865.getType().hasName("size_t")
and voffs_865.getType().hasName("size_t")
and v__FUNCTION__.getType() instanceof ArrayType
and v_ret_911.getType().hasName("int")
and vctx_860.getParentScope+() = func
and vinfo_blob_864.getParentScope+() = func
and vinfo_len_865.getParentScope+() = func
and vlabel_len_865.getParentScope+() = func
and voffs_865.getParentScope+() = func
and not v__FUNCTION__.getParentScope+() = func
and v_ret_911.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
