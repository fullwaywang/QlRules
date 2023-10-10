/**
 * @name linux-c30f1fc041b74ecdb072dd44f858750414b8b19f-inet_frag_destroy
 * @id cpp/linux/c30f1fc041b74ecdb072dd44f858750414b8b19f/inet-frag-destroy
 * @description linux-c30f1fc041b74ecdb072dd44f858750414b8b19f-inet_frag_destroy 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsum_truesize_130, Parameter vq_126, Variable vfp_128, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vfp_128
		and target_0.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(VariableAccess).getTarget()=vfp_128
		and target_0.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt() instanceof BlockStmt
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsum_truesize_130
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("skb_rbtree_purge")
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rb_fragments"
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_126
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

predicate func_3(Variable vsum_truesize_130, Variable vxp_141, Variable vfp_128) {
	exists(BlockStmt target_3 |
		target_3.getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getTarget().getName()="next"
		and target_3.getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_3.getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_3.getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfp_128
		and target_3.getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vsum_truesize_130
		and target_3.getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="truesize"
		and target_3.getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfp_128
		and target_3.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree_skb")
		and target_3.getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfp_128
		and target_3.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfp_128
		and target_3.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vxp_141
		and target_3.getParent().(WhileStmt).getCondition().(VariableAccess).getTarget()=vfp_128)
}

predicate func_5(Variable vfp_128, Function func) {
	exists(WhileStmt target_5 |
		target_5.getCondition().(VariableAccess).getTarget()=vfp_128
		and target_5.getStmt() instanceof BlockStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_6(Parameter vq_126) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="net"
		and target_6.getQualifier().(VariableAccess).getTarget()=vq_126)
}

predicate func_7(Parameter vq_126, Variable vfp_128) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(VariableAccess).getTarget()=vfp_128
		and target_7.getRValue().(PointerFieldAccess).getTarget().getName()="fragments"
		and target_7.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vq_126)
}

from Function func, Variable vsum_truesize_130, Variable vxp_141, Parameter vq_126, Variable vfp_128
where
not func_0(vsum_truesize_130, vq_126, vfp_128, func)
and func_3(vsum_truesize_130, vxp_141, vfp_128)
and func_5(vfp_128, func)
and vsum_truesize_130.getType().hasName("unsigned int")
and vxp_141.getType().hasName("sk_buff *")
and vq_126.getType().hasName("inet_frag_queue *")
and func_6(vq_126)
and vfp_128.getType().hasName("sk_buff *")
and func_7(vq_126, vfp_128)
and vsum_truesize_130.getParentScope+() = func
and vxp_141.getParentScope+() = func
and vq_126.getParentScope+() = func
and vfp_128.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
