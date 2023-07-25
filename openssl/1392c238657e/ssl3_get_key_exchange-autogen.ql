/**
 * @name openssl-1392c238657e-ssl3_get_key_exchange
 * @id cpp/openssl/1392c238657e/ssl3-get-key-exchange
 * @description openssl-1392c238657e-ssl/s3_clnt.c-ssl3_get_key_exchange CVE-2015-3196
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtmp_id_hint_1243, FunctionCall target_0) {
		target_0.getTarget().hasName("BUF_strdup")
		and not target_0.getTarget().hasName("BUF_strndup")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vtmp_id_hint_1243
}

predicate func_1(Parameter vs_1144, PointerFieldAccess target_19, PointerFieldAccess target_20) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="session"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_1144
		and target_19.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getQualifier().(VariableAccess).getLocation())
		and target_1.getQualifier().(VariableAccess).getLocation().isBefore(target_20.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vs_1144, EqualityOperation target_11, ExprStmt target_14) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="session"
		and target_2.getQualifier().(VariableAccess).getTarget()=vs_1144
		and target_11.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getQualifier().(VariableAccess).getLocation())
		and target_2.getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vp_1150, VariableAccess target_3) {
		target_3.getTarget()=vp_1150
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_4(Variable vi_1152, VariableAccess target_4) {
		target_4.getTarget()=vi_1152
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_5(Parameter vs_1144, VariableAccess target_5) {
		target_5.getTarget()=vs_1144
}

predicate func_7(Parameter vs_1144, VariableAccess target_7) {
		target_7.getTarget()=vs_1144
}

predicate func_8(BitwiseAndExpr target_21, Function func, DeclStmt target_8) {
		target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Variable vp_1150, Variable vi_1152, Variable vtmp_id_hint_1243, FunctionCall target_9) {
		target_9.getTarget().hasName("memcpy")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vtmp_id_hint_1243
		and target_9.getArgument(1).(VariableAccess).getTarget()=vp_1150
		and target_9.getArgument(2).(VariableAccess).getTarget()=vi_1152
}

predicate func_10(Variable vi_1152, Variable vtmp_id_hint_1243, BitwiseAndExpr target_21, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_10.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vtmp_id_hint_1243
		and target_10.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vi_1152
		and target_10.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_10.getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(AddExpr).getValue()="129"
		and target_10.getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vi_1152
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_11(Parameter vs_1144, ExprStmt target_13, EqualityOperation target_11) {
		target_11.getAnOperand().(PointerFieldAccess).getTarget().getName()="psk_identity_hint"
		and target_11.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_11.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1144
		and target_11.getAnOperand() instanceof Literal
		and target_11.getParent().(IfStmt).getThen()=target_13
}

/*predicate func_12(Parameter vs_1144, PointerFieldAccess target_19, PointerFieldAccess target_20, PointerFieldAccess target_12) {
		target_12.getTarget().getName()="ctx"
		and target_12.getQualifier().(VariableAccess).getTarget()=vs_1144
		and target_19.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getQualifier().(VariableAccess).getLocation())
		and target_12.getQualifier().(VariableAccess).getLocation().isBefore(target_20.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_13(Parameter vs_1144, EqualityOperation target_11, ExprStmt target_14, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="psk_identity_hint"
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1144
		and target_13.getParent().(IfStmt).getCondition()=target_11
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_14(Parameter vs_1144, BitwiseAndExpr target_21, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="psk_identity_hint"
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1144
		and target_14.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

/*predicate func_15(Parameter vs_1144, PointerFieldAccess target_20, EqualityOperation target_22, PointerFieldAccess target_15) {
		target_15.getTarget().getName()="ctx"
		and target_15.getQualifier().(VariableAccess).getTarget()=vs_1144
		and target_20.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_15.getQualifier().(VariableAccess).getLocation())
		and target_15.getQualifier().(VariableAccess).getLocation().isBefore(target_22.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_16(Variable val_1151, Parameter vs_1144, BitwiseAndExpr target_21, IfStmt target_16) {
		target_16.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="psk_identity_hint"
		and target_16.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_16.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1144
		and target_16.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val_1151
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="40"
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BitwiseOrExpr).getValue()="65"
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_16.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_16.getThen().(BlockStmt).getStmt(2).(GotoStmt).getName() ="f_err"
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

/*predicate func_17(Parameter vs_1144, ExprStmt target_14, PointerFieldAccess target_23, PointerFieldAccess target_17) {
		target_17.getTarget().getName()="psk_identity_hint"
		and target_17.getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1144
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_23.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_19(Parameter vs_1144, PointerFieldAccess target_19) {
		target_19.getTarget().getName()="tmp"
		and target_19.getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_19.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1144
}

predicate func_20(Parameter vs_1144, PointerFieldAccess target_20) {
		target_20.getTarget().getName()="psk_identity_hint"
		and target_20.getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_20.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1144
}

predicate func_21(BitwiseAndExpr target_21) {
		target_21.getRightOperand().(Literal).getValue()="256"
}

predicate func_22(Parameter vs_1144, EqualityOperation target_22) {
		target_22.getAnOperand().(PointerFieldAccess).getTarget().getName()="psk_identity_hint"
		and target_22.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_22.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1144
		and target_22.getAnOperand() instanceof Literal
}

predicate func_23(Parameter vs_1144, PointerFieldAccess target_23) {
		target_23.getTarget().getName()="tmp"
		and target_23.getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_23.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1144
}

from Function func, Variable vp_1150, Variable val_1151, Variable vi_1152, Variable vtmp_id_hint_1243, Parameter vs_1144, FunctionCall target_0, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, VariableAccess target_7, DeclStmt target_8, FunctionCall target_9, ExprStmt target_10, EqualityOperation target_11, ExprStmt target_13, ExprStmt target_14, IfStmt target_16, PointerFieldAccess target_19, PointerFieldAccess target_20, BitwiseAndExpr target_21, EqualityOperation target_22, PointerFieldAccess target_23
where
func_0(vtmp_id_hint_1243, target_0)
and not func_1(vs_1144, target_19, target_20)
and not func_2(vs_1144, target_11, target_14)
and func_3(vp_1150, target_3)
and func_4(vi_1152, target_4)
and func_5(vs_1144, target_5)
and func_7(vs_1144, target_7)
and func_8(target_21, func, target_8)
and func_9(vp_1150, vi_1152, vtmp_id_hint_1243, target_9)
and func_10(vi_1152, vtmp_id_hint_1243, target_21, target_10)
and func_11(vs_1144, target_13, target_11)
and func_13(vs_1144, target_11, target_14, target_13)
and func_14(vs_1144, target_21, target_14)
and func_16(val_1151, vs_1144, target_21, target_16)
and func_19(vs_1144, target_19)
and func_20(vs_1144, target_20)
and func_21(target_21)
and func_22(vs_1144, target_22)
and func_23(vs_1144, target_23)
and vp_1150.getType().hasName("unsigned char *")
and val_1151.getType().hasName("int")
and vi_1152.getType().hasName("long")
and vtmp_id_hint_1243.getType().hasName("char[129]")
and vs_1144.getType().hasName("SSL *")
and vp_1150.getParentScope+() = func
and val_1151.getParentScope+() = func
and vi_1152.getParentScope+() = func
and vtmp_id_hint_1243.getParentScope+() = func
and vs_1144.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()