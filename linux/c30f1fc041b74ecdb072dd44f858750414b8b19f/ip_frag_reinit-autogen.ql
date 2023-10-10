/**
 * @name linux-c30f1fc041b74ecdb072dd44f858750414b8b19f-ip_frag_reinit
 * @id cpp/linux/c30f1fc041b74ecdb072dd44f858750414b8b19f/ip-frag-reinit
 * @description linux-c30f1fc041b74ecdb072dd44f858750414b8b19f-ip_frag_reinit 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsum_truesize_249) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getTarget()=vsum_truesize_249
		and target_0.getRValue().(FunctionCall).getTarget().hasName("skb_rbtree_purge")
		and target_0.getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="rb_fragments"
		and target_0.getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess)
}

predicate func_1(Parameter vqp_246) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(ValueFieldAccess).getTarget().getName()="rb_fragments"
		and target_1.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="q"
		and target_1.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqp_246
		and target_1.getRValue().(ClassAggregateLiteral).getValue()="{...}")
}

predicate func_2(Parameter vqp_246) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="q"
		and target_2.getQualifier().(VariableAccess).getTarget()=vqp_246)
}

predicate func_4(Function func) {
	exists(DeclStmt target_4 |
		target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_5(Variable vfp_248) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(VariableAccess).getTarget()=vfp_248
		and target_5.getRValue().(ValueFieldAccess).getTarget().getName()="fragments"
		and target_5.getRValue().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess)
}

predicate func_6(Variable vfp_248, Variable vsum_truesize_249, Variable vxp_258, Function func) {
	exists(DoStmt target_6 |
		target_6.getCondition().(VariableAccess).getTarget()=vfp_248
		and target_6.getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getTarget().getName()="next"
		and target_6.getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_6.getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_6.getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfp_248
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vsum_truesize_249
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="truesize"
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfp_248
		and target_6.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree_skb")
		and target_6.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfp_248
		and target_6.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfp_248
		and target_6.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vxp_258
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

from Function func, Parameter vqp_246, Variable vfp_248, Variable vsum_truesize_249, Variable vxp_258
where
not func_0(vsum_truesize_249)
and not func_1(vqp_246)
and func_2(vqp_246)
and func_4(func)
and func_5(vfp_248)
and func_6(vfp_248, vsum_truesize_249, vxp_258, func)
and vqp_246.getType().hasName("ipq *")
and vfp_248.getType().hasName("sk_buff *")
and vsum_truesize_249.getType().hasName("unsigned int")
and vxp_258.getType().hasName("sk_buff *")
and vqp_246.getParentScope+() = func
and vfp_248.getParentScope+() = func
and vsum_truesize_249.getParentScope+() = func
and vxp_258.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
