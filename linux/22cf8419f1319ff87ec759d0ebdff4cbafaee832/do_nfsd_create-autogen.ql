/**
 * @name linux-22cf8419f1319ff87ec759d0ebdff4cbafaee832-do_nfsd_create
 * @id cpp/linux/22cf8419f1319ff87ec759d0ebdff4cbafaee832/do_nfsd_create
 * @description linux-22cf8419f1319ff87ec759d0ebdff4cbafaee832-do_nfsd_create 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter viap_1353, Variable vdirp_1358, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="s_flags"
		and target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="i_sb"
		and target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdirp_1358
		and target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="65536"
		and target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="16"
		and target_0.getThen().(ExprStmt).getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ia_mode"
		and target_0.getThen().(ExprStmt).getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viap_1353
		and target_0.getThen().(ExprStmt).getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(FunctionCall).getTarget().hasName("current_umask")
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_0))
}

predicate func_1(Parameter viap_1353) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="ia_valid"
		and target_1.getQualifier().(VariableAccess).getTarget()=viap_1353)
}

predicate func_2(Variable vdentry_1357, Variable vdirp_1358) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vdirp_1358
		and target_2.getRValue().(FunctionCall).getTarget().hasName("d_inode")
		and target_2.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdentry_1357)
}

from Function func, Parameter viap_1353, Variable vdentry_1357, Variable vdirp_1358
where
not func_0(viap_1353, vdirp_1358, func)
and viap_1353.getType().hasName("iattr *")
and func_1(viap_1353)
and vdirp_1358.getType().hasName("inode *")
and func_2(vdentry_1357, vdirp_1358)
and viap_1353.getParentScope+() = func
and vdentry_1357.getParentScope+() = func
and vdirp_1358.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
