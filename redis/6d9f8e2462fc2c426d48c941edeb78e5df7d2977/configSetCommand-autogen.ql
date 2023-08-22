/**
 * @name redis-6d9f8e2462fc2c426d48c941edeb78e5df7d2977-configSetCommand
 * @id cpp/redis/6d9f8e2462fc2c426d48c941edeb78e5df7d2977/configSetCommand
 * @description redis-6d9f8e2462fc2c426d48c941edeb78e5df7d2977-src/config.c-configSetCommand CVE-2016-8339
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_5, Function func) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_0.getEnclosingFunction() = func)
}

/*predicate func_2(BlockStmt target_5, Function func) {
	exists(UnaryMinusExpr target_2 |
		target_2.getValue()="-1"
		and target_2.getParent().(EQExpr).getAnOperand() instanceof FunctionCall
		and target_2.getParent().(EQExpr).getAnOperand() instanceof UnaryMinusExpr
		and target_2.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_5
		and target_2.getEnclosingFunction() = func)
}

*/
predicate func_3(Variable vj_893, Variable vv_894, BlockStmt target_5, UnaryMinusExpr target_3) {
		target_3.getValue()="-1"
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("getClientTypeByName")
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vv_894
		and target_3.getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_893
		and target_3.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_5
}

/*predicate func_4(Variable vj_893, Variable vv_894, BlockStmt target_5, FunctionCall target_4) {
		target_4.getTarget().hasName("getClientTypeByName")
		and target_4.getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vv_894
		and target_4.getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_893
		and target_4.getParent().(EQExpr).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_4.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_5
}

*/
predicate func_5(Variable vv_894, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sdsfreesplitres")
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vv_894
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Variable vj_893, Variable vv_894, UnaryMinusExpr target_3, BlockStmt target_5
where
not func_0(target_5, func)
and func_3(vj_893, vv_894, target_5, target_3)
and func_5(vv_894, target_5)
and vj_893.getType().hasName("int")
and vv_894.getType().hasName("sds *")
and vj_893.(LocalVariable).getFunction() = func
and vv_894.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
