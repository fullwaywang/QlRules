/**
 * @name sqlite3-522ebfa7cee96fb325a22ea3a2464a63485886a8-lookupName
 * @id cpp/sqlite3/522ebfa7cee96fb325a22ea3a2464a63485886a8/lookupName
 * @description sqlite3-522ebfa7cee96fb325a22ea3a2464a63485886a8-src/resolve.c-lookupName CVE-2019-19317
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(LogicalAndExpr target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vpExpr_208, Variable vn_559, LogicalAndExpr target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(IfStmt target_1 |
		target_1.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tabFlags"
		and target_1.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="pTab"
		and target_1.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="y"
		and target_1.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_208
		and target_1.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="96"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="colFlags"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("Column *")
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="96"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_559
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getValue()="63"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vpExpr_208, LogicalAndExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="iColumn"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_208
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("SrcList_item *")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Variable vn_559, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_559
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getValue()="63"
}

predicate func_4(Variable vn_559, ExprStmt target_4) {
		target_4.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="colUsed"
		and target_4.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("SrcList_item *")
		and target_4.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_4.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vn_559
}

from Function func, Parameter vpExpr_208, Variable vn_559, LogicalAndExpr target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(target_2, func)
and not func_1(vpExpr_208, vn_559, target_2, target_3, target_4)
and func_2(vpExpr_208, target_2)
and func_3(vn_559, target_3)
and func_4(vn_559, target_4)
and vpExpr_208.getType().hasName("Expr *")
and vn_559.getType().hasName("int")
and vpExpr_208.getFunction() = func
and vn_559.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
