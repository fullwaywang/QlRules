/**
 * @name linux-3b30460c5b0ed762be75a004e924ec3f8711e032-crypto_ccm_auth
 * @id cpp/linux/3b30460c5b0ed762be75a004e924ec3f8711e032/crypto-ccm-auth
 * @description linux-3b30460c5b0ed762be75a004e924ec3f8711e032-crypto_ccm_auth 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpctx_180) {
	exists(VariableDeclarationEntry target_0 |
		target_0.getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="odata"
		and target_0.getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpctx_180)
}

predicate func_1(Variable vpctx_180) {
	exists(VariableDeclarationEntry target_1 |
		target_1.getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="idata"
		and target_1.getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpctx_180)
}

predicate func_8(Function func) {
	exists(VariableDeclarationEntry target_8 |
		target_8.getType() instanceof ArrayType
		and target_8.getDeclaration().getParentScope+() = func)
}

predicate func_9(Function func) {
	exists(VariableDeclarationEntry target_9 |
		target_9.getType() instanceof ArrayType
		and target_9.getDeclaration().getParentScope+() = func)
}

predicate func_10(Parameter vcryptlen_178, Parameter vreq_177, Variable vodata_1_186) {
	exists(VariableAccess target_10 |
		target_10.getTarget()=vodata_1_186
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("format_input")
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vreq_177
		and target_10.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcryptlen_178)
}

predicate func_12(Variable vassoclen_184, Variable vidata_1_187) {
	exists(VariableAccess target_12 |
		target_12.getTarget()=vidata_1_187
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("format_adata")
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vassoclen_184)
}

predicate func_16(Parameter vcryptlen_178, Parameter vreq_177, Variable vodata_1_186) {
	exists(FunctionCall target_16 |
		target_16.getTarget().hasName("format_input")
		and target_16.getArgument(0).(VariableAccess).getTarget()=vodata_1_186
		and target_16.getArgument(1).(VariableAccess).getTarget()=vreq_177
		and target_16.getArgument(2).(VariableAccess).getTarget()=vcryptlen_178)
}

predicate func_17(Variable vassoclen_184, Variable vidata_1_187) {
	exists(FunctionCall target_17 |
		target_17.getTarget().hasName("format_adata")
		and target_17.getArgument(0).(VariableAccess).getTarget()=vidata_1_187
		and target_17.getArgument(1).(VariableAccess).getTarget()=vassoclen_184)
}

predicate func_18(Variable vsg_185, Variable vidata_1_187, Variable vilen_188) {
	exists(FunctionCall target_18 |
		target_18.getTarget().hasName("sg_set_buf")
		and target_18.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsg_185
		and target_18.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_18.getArgument(1).(VariableAccess).getTarget()=vidata_1_187
		and target_18.getArgument(2).(VariableAccess).getTarget()=vilen_188)
}

predicate func_19(Variable vidata_1_187, Variable vilen_188) {
	exists(FunctionCall target_19 |
		target_19.getTarget().hasName("__memset")
		and target_19.getArgument(0).(VariableAccess).getTarget()=vidata_1_187
		and target_19.getArgument(1).(Literal).getValue()="0"
		and target_19.getArgument(2).(VariableAccess).getTarget()=vilen_188)
}

from Function func, Parameter vcryptlen_178, Variable vpctx_180, Parameter vreq_177, Variable vassoclen_184, Variable vsg_185, Variable vodata_1_186, Variable vidata_1_187, Variable vilen_188
where
not func_0(vpctx_180)
and not func_1(vpctx_180)
and func_8(func)
and func_9(func)
and func_10(vcryptlen_178, vreq_177, vodata_1_186)
and func_12(vassoclen_184, vidata_1_187)
and vcryptlen_178.getType().hasName("unsigned int")
and vpctx_180.getType().hasName("crypto_ccm_req_priv_ctx *")
and vreq_177.getType().hasName("aead_request *")
and vassoclen_184.getType().hasName("unsigned int")
and vsg_185.getType().hasName("scatterlist[3]")
and func_16(vcryptlen_178, vreq_177, vodata_1_186)
and func_17(vassoclen_184, vidata_1_187)
and func_18(vsg_185, vidata_1_187, vilen_188)
and func_19(vidata_1_187, vilen_188)
and vilen_188.getType().hasName("int")
and vcryptlen_178.getParentScope+() = func
and vpctx_180.getParentScope+() = func
and vreq_177.getParentScope+() = func
and vassoclen_184.getParentScope+() = func
and vsg_185.getParentScope+() = func
and vodata_1_186.getParentScope+() = func
and vidata_1_187.getParentScope+() = func
and vilen_188.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
