/**
 * @name linux-4afa5f9617927453ac04b24b584f6c718dfb4f45-hash_accept
 * @id cpp/linux/4afa5f9617927453ac04b24b584f6c718dfb4f45/hash_accept
 * @description linux-4afa5f9617927453ac04b24b584f6c718dfb4f45-hash_accept 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1"
		and not target_0.getValue()="0"
		and target_0.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue() instanceof PointerFieldAccess
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and func.getEntryPoint().(BlockStmt).getStmt(10)=target_1)
}

predicate func_2(Variable vsk_176) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("lock_sock")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vsk_176)
}

predicate func_4(Variable vctx_178) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="more"
		and target_4.getQualifier().(VariableAccess).getTarget()=vctx_178)
}

predicate func_5(Variable verr_184, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_184
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getType().hasName("bool")
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen() instanceof FunctionCall
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_5))
}

predicate func_7(Variable vsk_176, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("release_sock")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_176
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_7))
}

predicate func_8(Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue() instanceof PointerFieldAccess
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("bool")
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_8))
}

predicate func_9(Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("bool")
		and target_9.getThen() instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_9))
}

predicate func_10(Variable verr_184, Function func) {
	exists(ReturnStmt target_10 |
		target_10.getExpr().(VariableAccess).getTarget()=verr_184
		and (func.getEntryPoint().(BlockStmt).getStmt(26)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(26).getFollowingStmt()=target_10))
}

predicate func_11(Variable vreq_179, Variable vstate_180) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("crypto_ahash_export")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vreq_179
		and target_11.getArgument(1).(VariableAccess).getTarget()=vstate_180)
}

predicate func_12(Variable vctx2_183) {
	exists(PointerFieldAccess target_12 |
		target_12.getTarget().getName()="more"
		and target_12.getQualifier().(VariableAccess).getTarget()=vctx2_183)
}

predicate func_14(Variable vsk_176) {
	exists(FunctionCall target_14 |
		target_14.getTarget().hasName("alg_sk")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vsk_176)
}

predicate func_15(Variable vctx_178) {
	exists(PointerFieldAccess target_15 |
		target_15.getTarget().getName()="req"
		and target_15.getQualifier().(VariableAccess).getTarget()=vctx_178)
}

predicate func_16(Variable vsk2_181, Variable verr_184, Function func) {
	exists(IfStmt target_16 |
		target_16.getCondition().(VariableAccess).getTarget()=verr_184
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sock_orphan")
		and target_16.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk2_181
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sock_put")
		and target_16.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk2_181
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_16)
}

from Function func, Variable vsk_176, Variable vctx_178, Variable vreq_179, Variable vstate_180, Variable vsk2_181, Variable vctx2_183, Variable verr_184
where
func_0(func)
and not func_1(func)
and not func_2(vsk_176)
and not func_4(vctx_178)
and not func_5(verr_184, func)
and not func_7(vsk_176, func)
and not func_8(func)
and not func_9(func)
and not func_10(verr_184, func)
and func_11(vreq_179, vstate_180)
and func_12(vctx2_183)
and vsk_176.getType().hasName("sock *")
and func_14(vsk_176)
and vctx_178.getType().hasName("hash_ctx *")
and func_15(vctx_178)
and vreq_179.getType().hasName("ahash_request *")
and vstate_180.getType().hasName("char[]")
and vctx2_183.getType().hasName("hash_ctx *")
and verr_184.getType().hasName("int")
and func_16(vsk2_181, verr_184, func)
and vsk_176.getParentScope+() = func
and vctx_178.getParentScope+() = func
and vreq_179.getParentScope+() = func
and vstate_180.getParentScope+() = func
and vsk2_181.getParentScope+() = func
and vctx2_183.getParentScope+() = func
and verr_184.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
