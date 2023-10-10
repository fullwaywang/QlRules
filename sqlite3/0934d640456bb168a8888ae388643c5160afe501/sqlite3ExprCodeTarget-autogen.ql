/**
 * @name sqlite3-0934d640456bb168a8888ae388643c5160afe501-sqlite3ExprCodeTarget
 * @id cpp/sqlite3/0934d640456bb168a8888ae388643c5160afe501/sqlite3ExprCodeTarget
 * @description sqlite3-0934d640456bb168a8888ae388643c5160afe501-src/expr.c-sqlite3ExprCodeTarget CVE-2020-13435
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Variable vpCol_3814, ReturnStmt target_7) {
    exists(ExprStmt target_2 |
        target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpCol_3814
        and target_2.getExpr().(AssignExpr).getRValue() instanceof AddressOfExpr
        and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vpInfo_4113, Parameter vpExpr_3788, BlockStmt target_8, EqualityOperation target_5, ValueFieldAccess target_9) {
    exists(LogicalOrExpr target_3 |
        target_3.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
        and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="iAgg"
        and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_3788
        and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
        and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="iAgg"
        and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_3788
        and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="nFunc"
        and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpInfo_4113
        and target_3.getParent().(IfStmt).getThen()=target_8
        and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(VariableAccess).getLocation())
        and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vpExpr_3788, Variable vpAggInfo_3813, AddressOfExpr target_4) {
        target_4.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="aCol"
        and target_4.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpAggInfo_3813
        and target_4.getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="iAgg"
        and target_4.getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_3788
}

predicate func_5(Variable vpInfo_4113, BlockStmt target_8, EqualityOperation target_5) {
        target_5.getAnOperand().(VariableAccess).getTarget()=vpInfo_4113
        and target_5.getAnOperand().(Literal).getValue()="0"
        and target_5.getParent().(IfStmt).getThen()=target_8
}

predicate func_6(Function func, Initializer target_6) {
        target_6.getExpr() instanceof AddressOfExpr
        and target_6.getExpr().getEnclosingFunction() = func
}

predicate func_7(Variable vpCol_3814, ReturnStmt target_7) {
        target_7.getExpr().(PointerFieldAccess).getTarget().getName()="iMem"
        and target_7.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpCol_3814
}

predicate func_8(Parameter vpExpr_3788, BlockStmt target_8) {
        target_8.getStmt(0).(ExprStmt).getExpr().(Literal).getValue()="0"
        and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sqlite3ErrorMsg")
        and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Parse *")
        and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="misuse of aggregate: %s()"
        and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="zToken"
        and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="u"
        and target_8.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_3788
}

predicate func_9(Parameter vpExpr_3788, ValueFieldAccess target_9) {
        target_9.getTarget().getName()="zToken"
        and target_9.getQualifier().(PointerFieldAccess).getTarget().getName()="u"
        and target_9.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpExpr_3788
}

from Function func, Variable vpInfo_4113, Parameter vpExpr_3788, Variable vpAggInfo_3813, Variable vpCol_3814, AddressOfExpr target_4, EqualityOperation target_5, Initializer target_6, ReturnStmt target_7, BlockStmt target_8, ValueFieldAccess target_9
where
not func_2(vpCol_3814, target_7)
and not func_3(vpInfo_4113, vpExpr_3788, target_8, target_5, target_9)
and func_4(vpExpr_3788, vpAggInfo_3813, target_4)
and func_5(vpInfo_4113, target_8, target_5)
and func_6(func, target_6)
and func_7(vpCol_3814, target_7)
and func_8(vpExpr_3788, target_8)
and func_9(vpExpr_3788, target_9)
and vpInfo_4113.getType().hasName("AggInfo *")
and vpExpr_3788.getType().hasName("Expr *")
and vpAggInfo_3813.getType().hasName("AggInfo *")
and vpCol_3814.getType().hasName("AggInfo_col *")
and vpInfo_4113.(LocalVariable).getFunction() = func
and vpExpr_3788.getFunction() = func
and vpAggInfo_3813.(LocalVariable).getFunction() = func
and vpCol_3814.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
