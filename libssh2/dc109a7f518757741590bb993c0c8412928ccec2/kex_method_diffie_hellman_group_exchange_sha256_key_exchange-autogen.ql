/**
 * @name libssh2-dc109a7f518757741590bb993c0c8412928ccec2-kex_method_diffie_hellman_group_exchange_sha256_key_exchange
 * @id cpp/libssh2/dc109a7f518757741590bb993c0c8412928ccec2/kex-method-diffie-hellman-group-exchange-sha256-key-exchange
 * @description libssh2-dc109a7f518757741590bb993c0c8412928ccec2-src/kex.c-kex_method_diffie_hellman_group_exchange_sha256_key_exchange CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vkey_state_1686, Variable vp_len_1688, Variable vs_1747, VariableAccess target_0) {
		target_0.getTarget()=vs_1747
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_bin2bn")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_len_1688
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1686
}

predicate func_1(Parameter vkey_state_1686, Variable vg_len_1688, Variable vs_1747, VariableAccess target_1) {
		target_1.getTarget()=vs_1747
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BN_bin2bn")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vg_len_1688
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="g"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1686
}

predicate func_2(Parameter vkey_state_1686, Initializer target_2) {
		target_2.getExpr().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getExpr().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1686
		and target_2.getExpr().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
}

/*predicate func_3(Parameter vkey_state_1686, EqualityOperation target_27, Literal target_3) {
		target_3.getValue()="1"
		and not target_3.getValue()="0"
		and target_3.getParent().(PointerAddExpr).getParent().(Initializer).getExpr().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getParent().(PointerAddExpr).getParent().(Initializer).getExpr().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1686
		and target_27.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getParent().(PointerAddExpr).getParent().(Initializer).getExpr().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_4(Variable vs_1747, VariableAccess target_4) {
		target_4.getTarget()=vs_1747
}

predicate func_5(Function func, Literal target_5) {
		target_5.getValue()="4"
		and not target_5.getValue()="0"
		and target_5.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Variable vs_1747, VariableAccess target_6) {
		target_6.getTarget()=vs_1747
}

predicate func_7(Function func, Literal target_7) {
		target_7.getValue()="4"
		and not target_7.getValue()="9"
		and target_7.getParent().(AssignPointerAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignPointerAddExpr
		and target_7.getEnclosingFunction() = func
}

predicate func_10(Parameter vsession_1686, Parameter vkey_state_1686, Variable vret_1689, EqualityOperation target_27, ExprStmt target_28, PointerArithmeticOperation target_29) {
	exists(IfStmt target_10 |
		target_10.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_10.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1686
		and target_10.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="9"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1689
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1686
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected key length"
		and target_10.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_10.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="dh_gex_clean_exit"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_10
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_27
		and target_28.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_29.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_11(Parameter vsession_1686, Variable vret_1689, ExprStmt target_28) {
	exists(AssignExpr target_11 |
		target_11.getLValue().(VariableAccess).getTarget()=vret_1689
		and target_11.getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_11.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1686
		and target_11.getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_11.getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected key length"
		and target_28.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
predicate func_12(Parameter vkey_state_1686, ExprStmt target_30) {
	exists(AssignExpr target_12 |
		target_12.getLValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_12.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_12.getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_12.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1686
		and target_12.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_30.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_13(Function func) {
	exists(AssignExpr target_13 |
		target_13.getLValue().(ValueFieldAccess).getTarget().getName()="dataptr"
		and target_13.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_13.getRValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_13.getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Parameter vkey_state_1686, ExprStmt target_30, ExprStmt target_31) {
	exists(AssignExpr target_14 |
		target_14.getLValue().(ValueFieldAccess).getTarget().getName()="len"
		and target_14.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_14.getRValue().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_14.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1686
		and target_30.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_31.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_15(Function func) {
	exists(PostfixIncrExpr target_15 |
		target_15.getOperand().(ValueFieldAccess).getTarget().getName()="dataptr"
		and target_15.getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("string_buf")
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Parameter vsession_1686, Variable vp_len_1688, Variable vret_1689, EqualityOperation target_27, ExprStmt target_30) {
	exists(IfStmt target_16 |
		target_16.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_len_1688
		and target_16.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_get_bignum_bytes")
		and target_16.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_16.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("unsigned char *")
		and target_16.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1689
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1686
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected value"
		and target_16.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_16.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="dh_gex_clean_exit"
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(8)=target_16
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_27
		and target_16.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_30.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

/*predicate func_17(Function func) {
	exists(FunctionCall target_17 |
		target_17.getTarget().hasName("_libssh2_get_bignum_bytes")
		and target_17.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_17.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("unsigned char *")
		and target_17.getEnclosingFunction() = func)
}

*/
predicate func_18(Parameter vsession_1686, Variable vg_len_1688, Variable vret_1689, EqualityOperation target_27, ExprStmt target_32, ExprStmt target_31) {
	exists(IfStmt target_18 |
		target_18.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vg_len_1688
		and target_18.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_get_bignum_bytes")
		and target_18.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_18.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("unsigned char *")
		and target_18.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_18.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1689
		and target_18.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_18.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1686
		and target_18.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-14"
		and target_18.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unexpected value"
		and target_18.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_18.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="dh_gex_clean_exit"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(9)=target_18
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_27
		and target_18.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_18.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_31.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

/*predicate func_19(Function func) {
	exists(FunctionCall target_19 |
		target_19.getTarget().hasName("_libssh2_get_bignum_bytes")
		and target_19.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("string_buf")
		and target_19.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("unsigned char *")
		and target_19.getEnclosingFunction() = func)
}

*/
predicate func_20(Function func, DeclStmt target_20) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_20
}

predicate func_21(Parameter vkey_state_1686, PointerFieldAccess target_21) {
		target_21.getTarget().getName()="data"
		and target_21.getQualifier().(VariableAccess).getTarget()=vkey_state_1686
}

predicate func_22(Variable vs_1747, FunctionCall target_22) {
		target_22.getTarget().hasName("_libssh2_ntohu32")
		and target_22.getArgument(0).(VariableAccess).getTarget()=vs_1747
}

predicate func_23(Variable vs_1747, ExprStmt target_30, AssignPointerAddExpr target_23) {
		target_23.getLValue().(VariableAccess).getTarget()=vs_1747
		and target_23.getRValue() instanceof Literal
		and target_23.getLValue().(VariableAccess).getLocation().isBefore(target_30.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_24(Variable vp_len_1688, Variable vs_1747, AssignPointerAddExpr target_24) {
		target_24.getLValue().(VariableAccess).getTarget()=vs_1747
		and target_24.getRValue().(VariableAccess).getTarget()=vp_len_1688
}

predicate func_25(Variable vs_1747, FunctionCall target_25) {
		target_25.getTarget().hasName("_libssh2_ntohu32")
		and target_25.getArgument(0).(VariableAccess).getTarget()=vs_1747
}

predicate func_26(Variable vs_1747, ExprStmt target_31, AssignPointerAddExpr target_26) {
		target_26.getLValue().(VariableAccess).getTarget()=vs_1747
		and target_26.getRValue() instanceof Literal
		and target_26.getLValue().(VariableAccess).getLocation().isBefore(target_31.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_27(Parameter vkey_state_1686, EqualityOperation target_27) {
		target_27.getAnOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_27.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1686
}

predicate func_28(Parameter vsession_1686, Variable vret_1689, ExprStmt target_28) {
		target_28.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1689
		and target_28.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_28.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1686
		and target_28.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Timeout waiting for GEX_GROUP reply SHA256"
}

predicate func_29(Parameter vkey_state_1686, PointerArithmeticOperation target_29) {
		target_29.getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_29.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1686
		and target_29.getAnOperand() instanceof Literal
}

predicate func_30(Parameter vkey_state_1686, Variable vp_len_1688, Variable vs_1747, ExprStmt target_30) {
		target_30.getExpr().(FunctionCall).getTarget().hasName("BN_bin2bn")
		and target_30.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1747
		and target_30.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_len_1688
		and target_30.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="p"
		and target_30.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1686
}

predicate func_31(Parameter vkey_state_1686, Variable vg_len_1688, Variable vs_1747, ExprStmt target_31) {
		target_31.getExpr().(FunctionCall).getTarget().hasName("BN_bin2bn")
		and target_31.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1747
		and target_31.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vg_len_1688
		and target_31.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="g"
		and target_31.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1686
}

predicate func_32(Parameter vsession_1686, Parameter vkey_state_1686, Variable vp_len_1688, Variable vret_1689, ExprStmt target_32) {
		target_32.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1689
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("diffie_hellman_sha256")
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_1686
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="g"
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1686
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="p"
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1686
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vp_len_1688
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="32"
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="33"
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1686
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="data_len"
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1686
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="exchange_state"
		and target_32.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_state_1686
}

from Function func, Parameter vsession_1686, Parameter vkey_state_1686, Variable vp_len_1688, Variable vg_len_1688, Variable vret_1689, Variable vs_1747, VariableAccess target_0, VariableAccess target_1, Initializer target_2, VariableAccess target_4, Literal target_5, VariableAccess target_6, Literal target_7, DeclStmt target_20, PointerFieldAccess target_21, FunctionCall target_22, AssignPointerAddExpr target_23, AssignPointerAddExpr target_24, FunctionCall target_25, AssignPointerAddExpr target_26, EqualityOperation target_27, ExprStmt target_28, PointerArithmeticOperation target_29, ExprStmt target_30, ExprStmt target_31, ExprStmt target_32
where
func_0(vkey_state_1686, vp_len_1688, vs_1747, target_0)
and func_1(vkey_state_1686, vg_len_1688, vs_1747, target_1)
and func_2(vkey_state_1686, target_2)
and func_4(vs_1747, target_4)
and func_5(func, target_5)
and func_6(vs_1747, target_6)
and func_7(func, target_7)
and not func_10(vsession_1686, vkey_state_1686, vret_1689, target_27, target_28, target_29)
and not func_12(vkey_state_1686, target_30)
and not func_13(func)
and not func_14(vkey_state_1686, target_30, target_31)
and not func_15(func)
and not func_16(vsession_1686, vp_len_1688, vret_1689, target_27, target_30)
and not func_18(vsession_1686, vg_len_1688, vret_1689, target_27, target_32, target_31)
and func_20(func, target_20)
and func_21(vkey_state_1686, target_21)
and func_22(vs_1747, target_22)
and func_23(vs_1747, target_30, target_23)
and func_24(vp_len_1688, vs_1747, target_24)
and func_25(vs_1747, target_25)
and func_26(vs_1747, target_31, target_26)
and func_27(vkey_state_1686, target_27)
and func_28(vsession_1686, vret_1689, target_28)
and func_29(vkey_state_1686, target_29)
and func_30(vkey_state_1686, vp_len_1688, vs_1747, target_30)
and func_31(vkey_state_1686, vg_len_1688, vs_1747, target_31)
and func_32(vsession_1686, vkey_state_1686, vp_len_1688, vret_1689, target_32)
and vsession_1686.getType().hasName("LIBSSH2_SESSION *")
and vkey_state_1686.getType().hasName("key_exchange_state_low_t *")
and vp_len_1688.getType().hasName("unsigned long")
and vg_len_1688.getType().hasName("unsigned long")
and vret_1689.getType().hasName("int")
and vs_1747.getType().hasName("unsigned char *")
and vsession_1686.getParentScope+() = func
and vkey_state_1686.getParentScope+() = func
and vp_len_1688.getParentScope+() = func
and vg_len_1688.getParentScope+() = func
and vret_1689.getParentScope+() = func
and vs_1747.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
