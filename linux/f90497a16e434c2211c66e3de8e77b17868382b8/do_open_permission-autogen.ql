/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-do_open_permission
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/do-open-permission
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-do_open_permission 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrqstp_142, Parameter vcurrent_fh_142, Parameter vaccmode_142) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("fh_verify")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vrqstp_142
		and target_0.getArgument(1).(VariableAccess).getTarget()=vcurrent_fh_142
		and target_0.getArgument(2).(Literal).getValue()="32768"
		and target_0.getArgument(3).(VariableAccess).getTarget()=vaccmode_142)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Variable vstatus_144, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_144
		and target_2.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Variable vstatus_144) {
	exists(VariableAccess target_3 |
		target_3.getTarget()=vstatus_144)
}

from Function func, Parameter vrqstp_142, Parameter vcurrent_fh_142, Parameter vaccmode_142, Variable vstatus_144
where
func_0(vrqstp_142, vcurrent_fh_142, vaccmode_142)
and func_1(func)
and func_2(vstatus_144, func)
and func_3(vstatus_144)
and vrqstp_142.getType().hasName("svc_rqst *")
and vcurrent_fh_142.getType().hasName("svc_fh *")
and vaccmode_142.getType().hasName("int")
and vstatus_144.getType().hasName("__be32")
and vrqstp_142.getParentScope+() = func
and vcurrent_fh_142.getParentScope+() = func
and vaccmode_142.getParentScope+() = func
and vstatus_144.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
