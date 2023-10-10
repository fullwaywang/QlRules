/**
 * @name linux-f3554aeb991214cbfafd17d55e2bfddb50282e32-setup_format_params
 * @id cpp/linux/f3554aeb991214cbfafd17d55e2bfddb50282e32/setup_format_params
 * @description linux-f3554aeb991214cbfafd17d55e2bfddb50282e32-setup_format_params 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vraw_cmd, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cmd"
		and target_0.getCondition().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vraw_cmd
		and target_0.getCondition().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_0.getThen().(ReturnStmt).toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_0))
}

predicate func_1(Variable vraw_cmd) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="cmd"
		and target_1.getQualifier().(VariableAccess).getTarget()=vraw_cmd)
}

from Function func, Variable vraw_cmd
where
not func_0(vraw_cmd, func)
and vraw_cmd.getType().hasName("floppy_raw_cmd *")
and func_1(vraw_cmd)
and not vraw_cmd.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
