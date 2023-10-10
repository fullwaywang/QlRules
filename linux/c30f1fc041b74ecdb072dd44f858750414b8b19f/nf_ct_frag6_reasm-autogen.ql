/**
 * @name linux-c30f1fc041b74ecdb072dd44f858750414b8b19f-nf_ct_frag6_reasm
 * @id cpp/linux/c30f1fc041b74ecdb072dd44f858750414b8b19f/nf-ct-frag6-reasm
 * @description linux-c30f1fc041b74ecdb072dd44f858750414b8b19f-nf_ct_frag6_reasm 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vfq_341, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="rb_fragments"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="q"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfq_341
		and target_1.getExpr().(AssignExpr).getRValue().(ClassAggregateLiteral).getValue()="{...}"
		and (func.getEntryPoint().(BlockStmt).getStmt(31)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(31).getFollowingStmt()=target_1))
}

predicate func_2(Variable vhead_343) {
	exists(ValueFieldAccess target_2 |
		target_2.getTarget().getName()="(unknown field)"
		and target_2.getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_2.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_2.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhead_343)
}

predicate func_3(Variable vhead_343) {
	exists(EqualityOperation target_3 |
		target_3.getAnOperand().(VariableAccess).getTarget()=vhead_343
		and target_3.getAnOperand() instanceof Literal)
}

predicate func_4(Parameter vfq_341) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="q"
		and target_4.getQualifier().(VariableAccess).getTarget()=vfq_341)
}

from Function func, Variable vhead_343, Parameter vfq_341
where
not func_1(vfq_341, func)
and func_2(vhead_343)
and vhead_343.getType().hasName("sk_buff *")
and func_3(vhead_343)
and vfq_341.getType().hasName("frag_queue *")
and func_4(vfq_341)
and vhead_343.getParentScope+() = func
and vfq_341.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
