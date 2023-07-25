/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-hostkey_method_ssh_ecdsa_sig_verify
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/hostkey-method-ssh-ecdsa-sig-verify
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/hostkey.c-hostkey_method_ssh_ecdsa_sig_verify CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="27"
		and not target_0.getValue()="0"
		and target_0.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="4"
		and not target_1.getValue()="0"
		and target_1.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vr_len_1_648, FunctionCall target_33, VariableAccess target_2) {
		target_2.getTarget()=vr_len_1_648
		and target_2.getLocation().isBefore(target_33.getArgument(2).(VariableAccess).getLocation())
}

predicate func_3(Function func, Literal target_3) {
		target_3.getValue()="4"
		and not target_3.getValue()="19"
		and target_3.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_3.getEnclosingFunction() = func
}

predicate func_10(Parameter vsig_642) {
	exists(AssignExpr target_10 |
		target_10.getLValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_10.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_10.getRValue().(VariableAccess).getTarget()=vsig_642)
}

predicate func_11(Function func) {
	exists(AssignExpr target_11 |
		target_11.getLValue().(ValueFieldAccess).getTarget().getName()="dataptr"
		and target_11.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_11.getRValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_11.getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(ValueFieldAccess target_12 |
		target_12.getTarget().getName()="len"
		and target_12.getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Function func) {
	exists(IfStmt target_13 |
		target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("_libssh2_get_c_string")
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_13.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("unsigned char *")
		and target_13.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="19"
		and target_13.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_13 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_13))
}

predicate func_14(Function func) {
	exists(IfStmt target_14 |
		target_14.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("_libssh2_get_u32")
		and target_14.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_14.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_14.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_14.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_14.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8"
		and target_14.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_14 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_14))
}

predicate func_15(Variable vr_1_647, Variable vr_len_1_648, ExprStmt target_34, ExprStmt target_29, Function func) {
	exists(IfStmt target_15 |
		target_15.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_len_1_648
		and target_15.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_get_c_string")
		and target_15.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_15.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vr_1_647
		and target_15.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_15.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_15 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_15)
		and target_34.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_15.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_15.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_29.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_16(Variable vs_1_647, Variable vs_len_1_648, Function func) {
	exists(IfStmt target_16 |
		target_16.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_len_1_648
		and target_16.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_get_c_string")
		and target_16.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_16.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vs_1_647
		and target_16.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_16.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_16 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_16))
}

predicate func_17(Parameter vsig_642, Variable vp_647, VariableAccess target_17) {
		target_17.getTarget()=vsig_642
		and target_17.getParent().(AssignExpr).getRValue() = target_17
		and target_17.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_647
}

predicate func_23(Parameter vsig_642, Variable vp_647, AssignExpr target_23) {
		target_23.getLValue().(VariableAccess).getTarget()=vp_647
		and target_23.getRValue().(VariableAccess).getTarget()=vsig_642
}

predicate func_24(Variable vp_647, AssignPointerAddExpr target_24) {
		target_24.getLValue().(VariableAccess).getTarget()=vp_647
		and target_24.getRValue() instanceof Literal
}

predicate func_25(Variable vp_647, Variable vr_len_1_648, VariableAccess target_25) {
		target_25.getTarget()=vr_len_1_648
		and target_25.getParent().(AssignExpr).getLValue() = target_25
		and target_25.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_25.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_647
}

/*predicate func_26(Variable vp_647, ExprStmt target_27, FunctionCall target_26) {
		target_26.getTarget().hasName("_libssh2_ntohu32")
		and target_26.getArgument(0).(VariableAccess).getTarget()=vp_647
		and target_26.getArgument(0).(VariableAccess).getLocation().isBefore(target_27.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
}

*/
predicate func_27(Variable vp_647, ExprStmt target_34, ExprStmt target_28, Function func, ExprStmt target_27) {
		target_27.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_647
		and target_27.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_27
		and target_27.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_28.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_28(Variable vr_1_647, Variable vp_647, Function func, ExprStmt target_28) {
		target_28.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_1_647
		and target_28.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_647
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_28
}

predicate func_29(Variable vp_647, Variable vr_len_1_648, Function func, ExprStmt target_29) {
		target_29.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_647
		and target_29.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vr_len_1_648
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_29
}

predicate func_30(Variable vp_647, Variable vs_len_1_648, Function func, ExprStmt target_30) {
		target_30.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_len_1_648
		and target_30.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_ntohu32")
		and target_30.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_647
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_30
}

predicate func_31(Variable vp_647, ExprStmt target_30, ExprStmt target_32, Function func, ExprStmt target_31) {
		target_31.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_647
		and target_31.getExpr().(AssignPointerAddExpr).getRValue() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_31
		and target_30.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_31.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_31.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_32.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_32(Variable vs_1_647, Variable vp_647, Function func, ExprStmt target_32) {
		target_32.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_1_647
		and target_32.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_647
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_32
}

predicate func_33(Variable vr_1_647, Variable vs_1_647, Variable vr_len_1_648, Variable vs_len_1_648, FunctionCall target_33) {
		target_33.getTarget().hasName("_libssh2_ecdsa_verify")
		and target_33.getArgument(1).(VariableAccess).getTarget()=vr_1_647
		and target_33.getArgument(2).(VariableAccess).getTarget()=vr_len_1_648
		and target_33.getArgument(3).(VariableAccess).getTarget()=vs_1_647
		and target_33.getArgument(4).(VariableAccess).getTarget()=vs_len_1_648
}

predicate func_34(Variable vr_len_1_648, ExprStmt target_34) {
		target_34.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_len_1_648
		and target_34.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

from Function func, Parameter vsig_642, Variable vr_1_647, Variable vs_1_647, Variable vp_647, Variable vr_len_1_648, Variable vs_len_1_648, Literal target_0, Literal target_1, VariableAccess target_2, Literal target_3, VariableAccess target_17, AssignExpr target_23, AssignPointerAddExpr target_24, VariableAccess target_25, ExprStmt target_27, ExprStmt target_28, ExprStmt target_29, ExprStmt target_30, ExprStmt target_31, ExprStmt target_32, FunctionCall target_33, ExprStmt target_34
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(vr_len_1_648, target_33, target_2)
and func_3(func, target_3)
and not func_10(vsig_642)
and not func_11(func)
and not func_12(func)
and not func_13(func)
and not func_14(func)
and not func_15(vr_1_647, vr_len_1_648, target_34, target_29, func)
and not func_16(vs_1_647, vs_len_1_648, func)
and func_17(vsig_642, vp_647, target_17)
and func_23(vsig_642, vp_647, target_23)
and func_24(vp_647, target_24)
and func_25(vp_647, vr_len_1_648, target_25)
and func_27(vp_647, target_34, target_28, func, target_27)
and func_28(vr_1_647, vp_647, func, target_28)
and func_29(vp_647, vr_len_1_648, func, target_29)
and func_30(vp_647, vs_len_1_648, func, target_30)
and func_31(vp_647, target_30, target_32, func, target_31)
and func_32(vs_1_647, vp_647, func, target_32)
and func_33(vr_1_647, vs_1_647, vr_len_1_648, vs_len_1_648, target_33)
and func_34(vr_len_1_648, target_34)
and vsig_642.getType().hasName("const unsigned char *")
and vr_1_647.getType().hasName("const unsigned char *")
and vs_1_647.getType().hasName("const unsigned char *")
and vp_647.getType().hasName("const unsigned char *")
and vr_len_1_648.getType().hasName("size_t")
and vs_len_1_648.getType().hasName("size_t")
and vsig_642.getParentScope+() = func
and vr_1_647.getParentScope+() = func
and vs_1_647.getParentScope+() = func
and vp_647.getParentScope+() = func
and vr_len_1_648.getParentScope+() = func
and vs_len_1_648.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
