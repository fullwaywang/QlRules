/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-idmap_name_to_id
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/idmap-name-to-id
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-idmap_name_to_id 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("strscpy")
		and target_0.getArgument(0) instanceof ValueFieldAccess
		and target_0.getArgument(1) instanceof FunctionCall
		and target_0.getArgument(2) instanceof SizeofExprOperator
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vkey_541) {
	exists(ValueFieldAccess target_1 |
		target_1.getTarget().getName()="authname"
		and target_1.getQualifier().(VariableAccess).getTarget()=vkey_541)
}

predicate func_2(Parameter vrqstp_538) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("rqst_authname")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vrqstp_538)
}

predicate func_3(Variable vkey_541) {
	exists(SizeofExprOperator target_3 |
		target_3.getValue()="128"
		and target_3.getExprOperand().(ValueFieldAccess).getTarget().getName()="authname"
		and target_3.getExprOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_541)
}

predicate func_4(Function func) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("strlcpy")
		and target_4.getArgument(0) instanceof ValueFieldAccess
		and target_4.getArgument(1) instanceof FunctionCall
		and target_4.getArgument(2) instanceof SizeofExprOperator
		and target_4.getEnclosingFunction() = func)
}

from Function func, Variable vkey_541, Parameter vrqstp_538
where
not func_0(func)
and func_1(vkey_541)
and func_2(vrqstp_538)
and func_3(vkey_541)
and func_4(func)
and vkey_541.getType().hasName("ent")
and vrqstp_538.getType().hasName("svc_rqst *")
and vkey_541.getParentScope+() = func
and vrqstp_538.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
