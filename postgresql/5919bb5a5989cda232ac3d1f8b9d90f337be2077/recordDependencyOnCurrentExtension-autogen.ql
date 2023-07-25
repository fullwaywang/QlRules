/**
 * @name postgresql-5919bb5a5989cda232ac3d1f8b9d90f337be2077-recordDependencyOnCurrentExtension
 * @id cpp/postgresql/5919bb5a5989cda232ac3d1f8b9d90f337be2077/recordDependencyOnCurrentExtension
 * @description postgresql-5919bb5a5989cda232ac3d1f8b9d90f337be2077-src/backend/catalog/pg_depend.c-recordDependencyOnCurrentExtension CVE-2022-2625
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable v__func__, VariableAccess target_1, FunctionCall target_2) {
	exists(DoStmt target_0 |
		target_0.getCondition() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("errfinish")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("errcode")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("errmsg")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s is not a member of extension \"%s\""
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("getObjectDescription")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("get_extension_name")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("errdetail")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(StringLiteral).getValue()="An extension is not allowed to replace an object that it does not own."
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getArgument(3).(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_1(Parameter visReplace_140, VariableAccess target_1) {
		target_1.getTarget()=visReplace_140
}

predicate func_2(Variable v__func__, FunctionCall target_2) {
		target_2.getTarget().hasName("errstart")
		and target_2.getArgument(0) instanceof Literal
		and target_2.getArgument(1) instanceof StringLiteral
		and target_2.getArgument(2) instanceof Literal
		and target_2.getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_2.getArgument(4) instanceof Literal
}

from Function func, Parameter visReplace_140, Variable v__func__, VariableAccess target_1, FunctionCall target_2
where
not func_0(v__func__, target_1, target_2)
and func_1(visReplace_140, target_1)
and func_2(v__func__, target_2)
and visReplace_140.getType().hasName("bool")
and v__func__.getType() instanceof ArrayType
and visReplace_140.getFunction() = func
and not v__func__.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
