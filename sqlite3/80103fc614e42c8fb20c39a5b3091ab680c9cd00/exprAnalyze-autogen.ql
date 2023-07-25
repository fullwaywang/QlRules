/**
 * @name sqlite3-80103fc614e42c8fb20c39a5b3091ab680c9cd00-exprAnalyze
 * @id cpp/sqlite3/80103fc614e42c8fb20c39a5b3091ab680c9cd00/exprAnalyze
 * @description sqlite3-80103fc614e42c8fb20c39a5b3091ab680c9cd00-src/where.c-exprAnalyze CVE-2015-3414
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpNewExpr1_1363, Variable vsCollSeqName_1367, Variable vpParse_1212, FunctionCall target_0) {
		target_0.getTarget().hasName("sqlite3ExprAddCollateToken")
		and not target_0.getTarget().hasName("sqlite3ExprAddCollateString")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vpParse_1212
		and target_0.getArgument(1).(VariableAccess).getTarget()=vpNewExpr1_1363
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsCollSeqName_1367
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3PExpr")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpParse_1212
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="83"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("Expr *")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

predicate func_1(Variable vpStr2_1362, Variable vpNewExpr2_1364, Variable vsCollSeqName_1367, Variable vpParse_1212, FunctionCall target_1) {
		target_1.getTarget().hasName("sqlite3ExprAddCollateToken")
		and not target_1.getTarget().hasName("sqlite3ExprAddCollateString")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vpParse_1212
		and target_1.getArgument(1).(VariableAccess).getTarget()=vpNewExpr2_1364
		and target_1.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsCollSeqName_1367
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3PExpr")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpParse_1212
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="82"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vpStr2_1362
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

predicate func_7(Variable vsCollSeqName_1367, ValueFieldAccess target_7) {
		target_7.getTarget().getName()="z"
		and target_7.getQualifier().(VariableAccess).getTarget()=vsCollSeqName_1367
		and target_7.getParent().(AssignExpr).getLValue() = target_7
		and target_7.getParent().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getParent().(AssignExpr).getRValue().(ConditionalExpr).getThen().(StringLiteral).getValue()="NOCASE"
		and target_7.getParent().(AssignExpr).getRValue().(ConditionalExpr).getElse().(StringLiteral).getValue()="BINARY"
}

predicate func_8(Variable vsCollSeqName_1367, AssignExpr target_8) {
		target_8.getLValue().(ValueFieldAccess).getTarget().getName()="n"
		and target_8.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsCollSeqName_1367
		and target_8.getRValue().(Literal).getValue()="6"
}

predicate func_9(Variable vsCollSeqName_1367, AddressOfExpr target_13, VariableAccess target_9) {
		target_9.getTarget()=vsCollSeqName_1367
		and target_9.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(FunctionCall).getArgument(2) instanceof FunctionCall
		and target_9.getLocation().isBefore(target_13.getOperand().(VariableAccess).getLocation())
}

predicate func_10(Variable vpStr2_1362, Variable vpNewExpr2_1364, Variable vpParse_1212, LogicalAndExpr target_14, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpNewExpr2_1364
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3PExpr")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpParse_1212
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="82"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof FunctionCall
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vpStr2_1362
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
}

predicate func_11(Variable vsCollSeqName_1367, AddressOfExpr target_15, VariableAccess target_11) {
		target_11.getTarget()=vsCollSeqName_1367
		and target_11.getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(FunctionCall).getArgument(2) instanceof FunctionCall
		and target_15.getOperand().(VariableAccess).getLocation().isBefore(target_11.getLocation())
}

predicate func_13(Variable vsCollSeqName_1367, AddressOfExpr target_13) {
		target_13.getOperand().(VariableAccess).getTarget()=vsCollSeqName_1367
}

predicate func_14(Variable vpParse_1212, LogicalAndExpr target_14) {
		target_14.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="op"
		and target_14.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("WhereClause *")
		and target_14.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="72"
		and target_14.getAnOperand().(FunctionCall).getTarget().hasName("isLikeOrGlob")
		and target_14.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpParse_1212
		and target_14.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Expr *")
		and target_14.getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("Expr *")
		and target_14.getAnOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_14.getAnOperand().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_15(Variable vsCollSeqName_1367, AddressOfExpr target_15) {
		target_15.getOperand().(VariableAccess).getTarget()=vsCollSeqName_1367
}

from Function func, Variable vpStr2_1362, Variable vpNewExpr1_1363, Variable vpNewExpr2_1364, Variable vsCollSeqName_1367, Variable vpParse_1212, FunctionCall target_0, FunctionCall target_1, ValueFieldAccess target_7, AssignExpr target_8, VariableAccess target_9, ExprStmt target_10, VariableAccess target_11, AddressOfExpr target_13, LogicalAndExpr target_14, AddressOfExpr target_15
where
func_0(vpNewExpr1_1363, vsCollSeqName_1367, vpParse_1212, target_0)
and func_1(vpStr2_1362, vpNewExpr2_1364, vsCollSeqName_1367, vpParse_1212, target_1)
and func_7(vsCollSeqName_1367, target_7)
and func_8(vsCollSeqName_1367, target_8)
and func_9(vsCollSeqName_1367, target_13, target_9)
and func_10(vpStr2_1362, vpNewExpr2_1364, vpParse_1212, target_14, target_10)
and func_11(vsCollSeqName_1367, target_15, target_11)
and func_13(vsCollSeqName_1367, target_13)
and func_14(vpParse_1212, target_14)
and func_15(vsCollSeqName_1367, target_15)
and vpStr2_1362.getType().hasName("Expr *")
and vpNewExpr1_1363.getType().hasName("Expr *")
and vpNewExpr2_1364.getType().hasName("Expr *")
and vsCollSeqName_1367.getType().hasName("Token")
and vpParse_1212.getType().hasName("Parse *")
and vpStr2_1362.(LocalVariable).getFunction() = func
and vpNewExpr1_1363.(LocalVariable).getFunction() = func
and vpNewExpr2_1364.(LocalVariable).getFunction() = func
and vsCollSeqName_1367.(LocalVariable).getFunction() = func
and vpParse_1212.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
