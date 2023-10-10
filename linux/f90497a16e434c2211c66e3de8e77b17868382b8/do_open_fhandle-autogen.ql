/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-do_open_fhandle
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/do-open-fhandle
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-do_open_fhandle 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vopen_454, Variable vcurrent_fh_456, Variable vaccmode_458, Parameter vrqstp_454) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("do_open_permission")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vrqstp_454
		and target_0.getArgument(1).(VariableAccess).getTarget()=vcurrent_fh_456
		and target_0.getArgument(2).(VariableAccess).getTarget()=vopen_454
		and target_0.getArgument(3).(VariableAccess).getTarget()=vaccmode_458)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Variable vstatus_457, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_457
		and target_2.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Variable vstatus_457) {
	exists(VariableAccess target_3 |
		target_3.getTarget()=vstatus_457)
}

from Function func, Parameter vopen_454, Variable vcurrent_fh_456, Variable vstatus_457, Variable vaccmode_458, Parameter vrqstp_454
where
func_0(vopen_454, vcurrent_fh_456, vaccmode_458, vrqstp_454)
and func_1(func)
and func_2(vstatus_457, func)
and func_3(vstatus_457)
and vopen_454.getType().hasName("nfsd4_open *")
and vcurrent_fh_456.getType().hasName("svc_fh *")
and vstatus_457.getType().hasName("__be32")
and vaccmode_458.getType().hasName("int")
and vrqstp_454.getType().hasName("svc_rqst *")
and vopen_454.getParentScope+() = func
and vcurrent_fh_456.getParentScope+() = func
and vstatus_457.getParentScope+() = func
and vaccmode_458.getParentScope+() = func
and vrqstp_454.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
