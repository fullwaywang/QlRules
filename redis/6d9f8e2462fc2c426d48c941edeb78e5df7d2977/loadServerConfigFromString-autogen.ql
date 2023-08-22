/**
 * @name redis-6d9f8e2462fc2c426d48c941edeb78e5df7d2977-loadServerConfigFromString
 * @id cpp/redis/6d9f8e2462fc2c426d48c941edeb78e5df7d2977/loadServerConfigFromString
 * @description redis-6d9f8e2462fc2c426d48c941edeb78e5df7d2977-src/config.c-loadServerConfigFromString CVE-2016-8339
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="Unrecognized client limit class"
		and not target_0.getValue()="Unrecognized client limit class: the user specified an invalid one, or 'master' which has no buffer limits."
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vclass_615, BlockStmt target_3, EqualityOperation target_2) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand() instanceof EqualityOperation
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclass_615
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_1.getParent().(IfStmt).getThen()=target_3
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vclass_615, BlockStmt target_3, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vclass_615
		and target_2.getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_2.getParent().(IfStmt).getThen()=target_3
}

predicate func_3(BlockStmt target_3) {
		target_3.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("char *")
		and target_3.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof StringLiteral
}

from Function func, Variable vclass_615, StringLiteral target_0, EqualityOperation target_2, BlockStmt target_3
where
func_0(func, target_0)
and not func_1(vclass_615, target_3, target_2)
and func_2(vclass_615, target_3, target_2)
and func_3(target_3)
and vclass_615.getType().hasName("int")
and vclass_615.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
