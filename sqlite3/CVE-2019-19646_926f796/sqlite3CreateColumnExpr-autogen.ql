/**
 * @name sqlite3-926f796e8feec15f3836aa0a060ed906f8ae04d3-sqlite3CreateColumnExpr
 * @id cpp/sqlite3/926f796e8feec15f3836aa0a060ed906f8ae04d3/sqlite3CreateColumnExpr
 * @description sqlite3-926f796e8feec15f3836aa0a060ed906f8ae04d3-src/resolve.c-sqlite3CreateColumnExpr CVE-2019-19646
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tabFlags"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("Table *")
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="96"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="colFlags"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("Column *")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="96"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof EmptyStmt
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof EmptyStmt
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="nCol"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="64"
		and target_0.getElse().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_0.getEnclosingFunction() = func)
}

/*predicate func_1(Variable vpItem_626) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="colUsed"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpItem_626
		and target_1.getRValue().(UnaryMinusExpr).getValue()="18446744073709551615")
}

*/
predicate func_2(Parameter viCol_623, Variable vpItem_626, EqualityOperation target_6, ExprStmt target_2) {
		target_2.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="colUsed"
		and target_2.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpItem_626
		and target_2.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=viCol_623
		and target_2.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getValue()="64"
		and target_2.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(ConditionalExpr).getThen().(SubExpr).getValue()="63"
		and target_2.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(ConditionalExpr).getElse().(VariableAccess).getTarget()=viCol_623
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

predicate func_3(Variable vp_624, Variable vpItem_626, AssignExpr target_3) {
		target_3.getLValue().(ValueFieldAccess).getTarget().getName()="pTab"
		and target_3.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="y"
		and target_3.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_624
		and target_3.getRValue().(PointerFieldAccess).getTarget().getName()="pTab"
		and target_3.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpItem_626
}

predicate func_4(EqualityOperation target_6, Function func, EmptyStmt target_4) {
		target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_4.getEnclosingFunction() = func
}

predicate func_5(EqualityOperation target_6, Function func, EmptyStmt target_5) {
		target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Parameter viCol_623, Variable vp_624, EqualityOperation target_6) {
		target_6.getAnOperand().(PointerFieldAccess).getTarget().getName()="iPKey"
		and target_6.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pTab"
		and target_6.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="y"
		and target_6.getAnOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_624
		and target_6.getAnOperand().(VariableAccess).getTarget()=viCol_623
}

from Function func, Parameter viCol_623, Variable vp_624, Variable vpItem_626, ExprStmt target_2, AssignExpr target_3, EmptyStmt target_4, EmptyStmt target_5, EqualityOperation target_6
where
not func_0(target_6, func)
and func_2(viCol_623, vpItem_626, target_6, target_2)
and func_3(vp_624, vpItem_626, target_3)
and func_4(target_6, func, target_4)
and func_5(target_6, func, target_5)
and func_6(viCol_623, vp_624, target_6)
and viCol_623.getType().hasName("int")
and vp_624.getType().hasName("Expr *")
and vpItem_626.getType().hasName("SrcList_item *")
and viCol_623.getFunction() = func
and vp_624.(LocalVariable).getFunction() = func
and vpItem_626.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
