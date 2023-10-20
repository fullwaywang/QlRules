/**
 * @name mbedtls-33f66ba6fd234114aa37f0209dac031bb2870a9b-ecdsa_sign_det_restartable
 * @id cpp/mbedtls/33f66ba6fd234114aa37f0209dac031bb2870a9b/ecdsa-sign-det-restartable
 * @description mbedtls-33f66ba6fd234114aa37f0209dac031bb2870a9b-library/ecdsa.c-ecdsa_sign_det_restartable CVE-2019-16910
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vgrp_404, Parameter vr_405, Parameter vs_405, Parameter vd_406, Parameter vbuf_406, Parameter vblen_406, Parameter vrs_ctx_408, Variable vret_410, Variable vp_rng_412, Variable vdata_413, Variable vgrp_len_414, Variable vmd_info_415, ExprStmt target_4, ExprStmt target_5, MulExpr target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("..(*)(..)")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_410
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ecdsa_sign_restartable")
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgrp_404
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vr_405
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_405
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vd_406
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vbuf_406
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vblen_406
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vp_rng_412
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getType().hasName("..(*)(..)")
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(9).(VariableAccess).getType().hasName("void *")
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vrs_ctx_408
		and target_0.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mbedtls_hmac_drbg_init")
		and target_0.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("mbedtls_hmac_drbg_context")
		and target_0.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("mbedtls_hmac_drbg_context *")
		and target_0.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("mbedtls_hmac_drbg_context")
		and target_0.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mbedtls_hmac_drbg_seed_buf")
		and target_0.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("mbedtls_hmac_drbg_context *")
		and target_0.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmd_info_415
		and target_0.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdata_413
		and target_0.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_0.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vgrp_len_414
		and target_0.getElse().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_410
		and target_0.getElse().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mbedtls_hmac_drbg_update_ret")
		and target_0.getElse().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("mbedtls_hmac_drbg_context *")
		and target_0.getElse().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("const char *")
		and target_0.getElse().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("strlen")
		and target_0.getElse().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("const char *")
		and target_0.getElse().(BlockStmt).getStmt(7).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_410
		and target_0.getElse().(BlockStmt).getStmt(7).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getElse().(BlockStmt).getStmt(7).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mbedtls_hmac_drbg_free")
		and target_0.getElse().(BlockStmt).getStmt(7).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_0.getElse().(BlockStmt).getStmt(7).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="cleanup"
		and target_0.getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_410
		and target_0.getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ecdsa_sign_restartable")
		and target_0.getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgrp_404
		and target_0.getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vr_405
		and target_0.getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_405
		and target_0.getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vd_406
		and target_0.getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vbuf_406
		and target_0.getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vblen_406
		and target_0.getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vp_rng_412
		and target_0.getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(9).(VariableAccess).getType().hasName("mbedtls_hmac_drbg_context *")
		and target_0.getElse().(BlockStmt).getStmt(8).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vrs_ctx_408
		and target_0.getElse().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mbedtls_hmac_drbg_free")
		and target_0.getElse().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("mbedtls_hmac_drbg_context")
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0)
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_6.getRightOperand().(VariableAccess).getLocation().isBefore(target_0.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(MulExpr).getRightOperand().(VariableAccess).getLocation()))
}

/*predicate func_3(Function func) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getType().hasName("mbedtls_hmac_drbg_context *")
		and target_3.getRValue().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("mbedtls_hmac_drbg_context")
		and target_3.getEnclosingFunction() = func)
}

*/
predicate func_4(Parameter vgrp_404, Parameter vr_405, Parameter vs_405, Parameter vd_406, Parameter vbuf_406, Parameter vblen_406, Parameter vrs_ctx_408, Variable vret_410, Variable vp_rng_412, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_410
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ecdsa_sign_restartable")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgrp_404
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vr_405
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_405
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vd_406
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vbuf_406
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vblen_406
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vp_rng_412
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vrs_ctx_408
}

predicate func_5(Variable vp_rng_412, Variable vdata_413, Variable vgrp_len_414, Variable vmd_info_415, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("mbedtls_hmac_drbg_seed_buf")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_rng_412
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmd_info_415
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdata_413
		and target_5.getExpr().(FunctionCall).getArgument(3).(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_5.getExpr().(FunctionCall).getArgument(3).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vgrp_len_414
}

predicate func_6(Variable vgrp_len_414, MulExpr target_6) {
		target_6.getLeftOperand().(Literal).getValue()="2"
		and target_6.getRightOperand().(VariableAccess).getTarget()=vgrp_len_414
}

from Function func, Parameter vgrp_404, Parameter vr_405, Parameter vs_405, Parameter vd_406, Parameter vbuf_406, Parameter vblen_406, Parameter vrs_ctx_408, Variable vret_410, Variable vp_rng_412, Variable vdata_413, Variable vgrp_len_414, Variable vmd_info_415, ExprStmt target_4, ExprStmt target_5, MulExpr target_6
where
not func_0(vgrp_404, vr_405, vs_405, vd_406, vbuf_406, vblen_406, vrs_ctx_408, vret_410, vp_rng_412, vdata_413, vgrp_len_414, vmd_info_415, target_4, target_5, target_6, func)
and func_4(vgrp_404, vr_405, vs_405, vd_406, vbuf_406, vblen_406, vrs_ctx_408, vret_410, vp_rng_412, target_4)
and func_5(vp_rng_412, vdata_413, vgrp_len_414, vmd_info_415, target_5)
and func_6(vgrp_len_414, target_6)
and vgrp_404.getType().hasName("mbedtls_ecp_group *")
and vr_405.getType().hasName("mbedtls_mpi *")
and vs_405.getType().hasName("mbedtls_mpi *")
and vd_406.getType().hasName("const mbedtls_mpi *")
and vbuf_406.getType().hasName("const unsigned char *")
and vblen_406.getType().hasName("size_t")
and vrs_ctx_408.getType().hasName("mbedtls_ecdsa_restart_ctx *")
and vret_410.getType().hasName("int")
and vp_rng_412.getType().hasName("mbedtls_hmac_drbg_context *")
and vdata_413.getType().hasName("unsigned char[132]")
and vgrp_len_414.getType().hasName("size_t")
and vmd_info_415.getType().hasName("const mbedtls_md_info_t *")
and vgrp_404.getParentScope+() = func
and vr_405.getParentScope+() = func
and vs_405.getParentScope+() = func
and vd_406.getParentScope+() = func
and vbuf_406.getParentScope+() = func
and vblen_406.getParentScope+() = func
and vrs_ctx_408.getParentScope+() = func
and vret_410.getParentScope+() = func
and vp_rng_412.getParentScope+() = func
and vdata_413.getParentScope+() = func
and vgrp_len_414.getParentScope+() = func
and vmd_info_415.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
