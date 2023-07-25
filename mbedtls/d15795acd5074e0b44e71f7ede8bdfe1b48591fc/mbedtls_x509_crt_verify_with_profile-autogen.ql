/**
 * @name mbedtls-d15795acd5074e0b44e71f7ede8bdfe1b48591fc-mbedtls_x509_crt_verify_with_profile
 * @id cpp/mbedtls/d15795acd5074e0b44e71f7ede8bdfe1b48591fc/mbedtls-x509-crt-verify-with-profile
 * @description mbedtls-d15795acd5074e0b44e71f7ede8bdfe1b48591fc-library/x509_crt.c-mbedtls_x509_crt_verify_with_profile CVE-2017-14032
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vret_2198, EqualityOperation target_17) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_2198
		and target_0.getExpr().(AssignExpr).getRValue() instanceof UnaryMinusExpr
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17)
}

predicate func_1(EqualityOperation target_17, Function func) {
	exists(GotoStmt target_1 |
		target_1.toString() = "goto ..."
		and target_1.getName() ="exit"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(EqualityOperation target_18, Function func) {
	exists(GotoStmt target_2 |
		target_2.toString() = "goto ..."
		and target_2.getName() ="exit"
		and target_2.getParent().(IfStmt).getCondition()=target_18
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(EqualityOperation target_19, Function func) {
	exists(GotoStmt target_3 |
		target_3.toString() = "goto ..."
		and target_3.getName() ="exit"
		and target_3.getParent().(IfStmt).getCondition()=target_19
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(EqualityOperation target_20, Function func) {
	exists(GotoStmt target_4 |
		target_4.toString() = "goto ..."
		and target_4.getName() ="exit"
		and target_4.getParent().(IfStmt).getCondition()=target_20
		and target_4.getEnclosingFunction() = func)
}

predicate func_6(Parameter vflags_2193, Variable vret_2198, ExprStmt target_9, EqualityOperation target_21, EqualityOperation target_19, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_2198
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vflags_2193
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="4294967295"
		and target_6.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_6)
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getLocation().isBefore(target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_21.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_19.getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vca_crl_2191, Parameter vprofile_2192, Parameter vflags_2193, Parameter vf_vrfy_2194, Parameter vp_vrfy_2195, Variable vret_2198, Variable vpathlen_2199, Variable vselfsigned_2199, Variable vparent_2200, Parameter vcrt_2189, EqualityOperation target_17, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_2198
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("x509_crt_verify_top")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcrt_2189
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vparent_2200
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vca_crl_2191
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vprofile_2192
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vpathlen_2199
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vselfsigned_2199
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vflags_2193
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vf_vrfy_2194
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vp_vrfy_2195
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
}

predicate func_8(Parameter vtrust_ca_2190, Parameter vca_crl_2191, Parameter vprofile_2192, Parameter vflags_2193, Parameter vf_vrfy_2194, Parameter vp_vrfy_2195, Variable vret_2198, Variable vpathlen_2199, Variable vselfsigned_2199, Variable vparent_2200, Parameter vcrt_2189, EqualityOperation target_22, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_2198
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("x509_crt_verify_child")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcrt_2189
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vparent_2200
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtrust_ca_2190
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vca_crl_2191
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vprofile_2192
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vpathlen_2199
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vselfsigned_2199
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vflags_2193
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vf_vrfy_2194
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(9).(VariableAccess).getTarget()=vp_vrfy_2195
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
}

predicate func_9(Parameter vtrust_ca_2190, Parameter vca_crl_2191, Parameter vprofile_2192, Parameter vflags_2193, Parameter vf_vrfy_2194, Parameter vp_vrfy_2195, Variable vret_2198, Variable vpathlen_2199, Variable vselfsigned_2199, Parameter vcrt_2189, EqualityOperation target_22, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_2198
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("x509_crt_verify_top")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcrt_2189
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtrust_ca_2190
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vca_crl_2191
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vprofile_2192
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vpathlen_2199
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vselfsigned_2199
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vflags_2193
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vf_vrfy_2194
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vp_vrfy_2195
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
}

predicate func_10(Function func, UnaryMinusExpr target_10) {
		target_10.getValue()="-10240"
		and target_10.getEnclosingFunction() = func
}

predicate func_11(Variable vret_2198, EqualityOperation target_18, ReturnStmt target_11) {
		target_11.getExpr().(VariableAccess).getTarget()=vret_2198
		and target_11.getParent().(IfStmt).getCondition()=target_18
}

predicate func_12(Variable vpathlen_2199, Variable vparent_2200, Parameter vcrt_2189, EqualityOperation target_17, BlockStmt target_12) {
		target_12.getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vparent_2200
		and target_12.getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_12.getStmt(0).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrt_2189
		and target_12.getStmt(0).(ForStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vparent_2200
		and target_12.getStmt(0).(ForStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getStmt(0).(ForStmt).getUpdate().(AssignExpr).getLValue().(VariableAccess).getTarget()=vparent_2200
		and target_12.getStmt(0).(ForStmt).getUpdate().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_12.getStmt(0).(ForStmt).getUpdate().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparent_2200
		and target_12.getStmt(0).(ForStmt).getStmt().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("x509_crt_check_parent")
		and target_12.getStmt(0).(ForStmt).getStmt().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcrt_2189
		and target_12.getStmt(0).(ForStmt).getStmt().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vparent_2200
		and target_12.getStmt(0).(ForStmt).getStmt().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_12.getStmt(0).(ForStmt).getStmt().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpathlen_2199
		and target_12.getStmt(0).(ForStmt).getStmt().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getStmt(0).(ForStmt).getStmt().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getStmt(0).(ForStmt).getStmt().(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_12.getStmt(1).(LabelStmt).toString() = "label ...:"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
}

predicate func_13(Variable vret_2198, VariableAccess target_13) {
		target_13.getTarget()=vret_2198
}

predicate func_14(EqualityOperation target_23, Function func, ReturnStmt target_14) {
		target_14.getExpr() instanceof UnaryMinusExpr
		and target_14.getParent().(IfStmt).getCondition()=target_23
		and target_14.getEnclosingFunction() = func
}

predicate func_15(Variable vret_2198, EqualityOperation target_19, ReturnStmt target_15) {
		target_15.getExpr().(VariableAccess).getTarget()=vret_2198
		and target_15.getParent().(IfStmt).getCondition()=target_19
}

predicate func_16(Variable vret_2198, EqualityOperation target_20, ReturnStmt target_16) {
		target_16.getExpr().(VariableAccess).getTarget()=vret_2198
		and target_16.getParent().(IfStmt).getCondition()=target_20
}

predicate func_17(Variable vparent_2200, EqualityOperation target_17) {
		target_17.getAnOperand().(VariableAccess).getTarget()=vparent_2200
		and target_17.getAnOperand().(Literal).getValue()="0"
}

predicate func_18(Variable vret_2198, EqualityOperation target_18) {
		target_18.getAnOperand().(VariableAccess).getTarget()=vret_2198
		and target_18.getAnOperand().(Literal).getValue()="0"
}

predicate func_19(Variable vret_2198, EqualityOperation target_19) {
		target_19.getAnOperand().(VariableAccess).getTarget()=vret_2198
		and target_19.getAnOperand().(Literal).getValue()="0"
}

predicate func_20(Variable vret_2198, EqualityOperation target_20) {
		target_20.getAnOperand().(VariableAccess).getTarget()=vret_2198
		and target_20.getAnOperand().(Literal).getValue()="0"
}

predicate func_21(Parameter vflags_2193, EqualityOperation target_21) {
		target_21.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vflags_2193
		and target_21.getAnOperand().(Literal).getValue()="0"
}

predicate func_22(Variable vparent_2200, EqualityOperation target_22) {
		target_22.getAnOperand().(VariableAccess).getTarget()=vparent_2200
		and target_22.getAnOperand().(Literal).getValue()="0"
}

predicate func_23(Parameter vprofile_2192, EqualityOperation target_23) {
		target_23.getAnOperand().(VariableAccess).getTarget()=vprofile_2192
		and target_23.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vtrust_ca_2190, Parameter vca_crl_2191, Parameter vprofile_2192, Parameter vflags_2193, Parameter vf_vrfy_2194, Parameter vp_vrfy_2195, Variable vret_2198, Variable vpathlen_2199, Variable vselfsigned_2199, Variable vparent_2200, Parameter vcrt_2189, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, UnaryMinusExpr target_10, ReturnStmt target_11, BlockStmt target_12, VariableAccess target_13, ReturnStmt target_14, ReturnStmt target_15, ReturnStmt target_16, EqualityOperation target_17, EqualityOperation target_18, EqualityOperation target_19, EqualityOperation target_20, EqualityOperation target_21, EqualityOperation target_22, EqualityOperation target_23
where
not func_0(vret_2198, target_17)
and not func_1(target_17, func)
and not func_2(target_18, func)
and not func_3(target_19, func)
and not func_4(target_20, func)
and not func_6(vflags_2193, vret_2198, target_9, target_21, target_19, func)
and func_7(vca_crl_2191, vprofile_2192, vflags_2193, vf_vrfy_2194, vp_vrfy_2195, vret_2198, vpathlen_2199, vselfsigned_2199, vparent_2200, vcrt_2189, target_17, target_7)
and func_8(vtrust_ca_2190, vca_crl_2191, vprofile_2192, vflags_2193, vf_vrfy_2194, vp_vrfy_2195, vret_2198, vpathlen_2199, vselfsigned_2199, vparent_2200, vcrt_2189, target_22, target_8)
and func_9(vtrust_ca_2190, vca_crl_2191, vprofile_2192, vflags_2193, vf_vrfy_2194, vp_vrfy_2195, vret_2198, vpathlen_2199, vselfsigned_2199, vcrt_2189, target_22, target_9)
and func_10(func, target_10)
and func_11(vret_2198, target_18, target_11)
and func_12(vpathlen_2199, vparent_2200, vcrt_2189, target_17, target_12)
and func_13(vret_2198, target_13)
and func_14(target_23, func, target_14)
and func_15(vret_2198, target_19, target_15)
and func_16(vret_2198, target_20, target_16)
and func_17(vparent_2200, target_17)
and func_18(vret_2198, target_18)
and func_19(vret_2198, target_19)
and func_20(vret_2198, target_20)
and func_21(vflags_2193, target_21)
and func_22(vparent_2200, target_22)
and func_23(vprofile_2192, target_23)
and vtrust_ca_2190.getType().hasName("mbedtls_x509_crt *")
and vca_crl_2191.getType().hasName("mbedtls_x509_crl *")
and vprofile_2192.getType().hasName("const mbedtls_x509_crt_profile *")
and vflags_2193.getType().hasName("uint32_t *")
and vf_vrfy_2194.getType().hasName("..(*)(..)")
and vp_vrfy_2195.getType().hasName("void *")
and vret_2198.getType().hasName("int")
and vpathlen_2199.getType().hasName("int")
and vselfsigned_2199.getType().hasName("int")
and vparent_2200.getType().hasName("mbedtls_x509_crt *")
and vcrt_2189.getType().hasName("mbedtls_x509_crt *")
and vtrust_ca_2190.getParentScope+() = func
and vca_crl_2191.getParentScope+() = func
and vprofile_2192.getParentScope+() = func
and vflags_2193.getParentScope+() = func
and vf_vrfy_2194.getParentScope+() = func
and vp_vrfy_2195.getParentScope+() = func
and vret_2198.getParentScope+() = func
and vpathlen_2199.getParentScope+() = func
and vselfsigned_2199.getParentScope+() = func
and vparent_2200.getParentScope+() = func
and vcrt_2189.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
