/**
 * @name postgresql-f02b9085ad2f6fefd9c5cdf85579cb9f0ff0f0ea-ExecEvalArrayExpr
 * @id cpp/postgresql/f02b9085ad2f6fefd9c5cdf85579cb9f0ff0f0ea/ExecEvalArrayExpr
 * @description postgresql-f02b9085ad2f6fefd9c5cdf85579cb9f0ff0f0ea-src/backend/executor/execExprInterp.c-ExecEvalArrayExpr CVE-2021-32027
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vndims_2673, Variable vdims_2674, NotExpr target_2, RelationalOperation target_3, ExprStmt target_4) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("ArrayGetNItems")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vndims_2673
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdims_2674
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(25)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vndims_2673, Variable vdims_2674, Variable vlbs_2675, NotExpr target_2, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("ArrayCheckBounds")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vndims_2673
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdims_2674
		and target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlbs_2675
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(26)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(NotExpr target_2) {
		target_2.getOperand().(ValueFieldAccess).getTarget().getName()="multidims"
		and target_2.getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="arrayexpr"
		and target_2.getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d"
		and target_2.getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ExprEvalStep *")
}

predicate func_3(Variable vndims_2673, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vndims_2673
}

predicate func_4(Variable vdims_2674, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdims_2674
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("int *")
		and target_4.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_6(Variable vndims_2673, Variable vdims_2674, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getValue()="16"
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdims_2674
		and target_6.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vndims_2673
		and target_6.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_6.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
}

predicate func_7(Variable vlbs_2675, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vlbs_2675
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("int *")
		and target_7.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_8(Variable vndims_2673, Variable vlbs_2675, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(SizeofTypeOperator).getValue()="16"
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(SizeofTypeOperator).getValue()="4"
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="ndim"
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlbs_2675
		and target_8.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vndims_2673
		and target_8.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_8.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
}

from Function func, Variable vndims_2673, Variable vdims_2674, Variable vlbs_2675, NotExpr target_2, RelationalOperation target_3, ExprStmt target_4, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8
where
not func_0(vndims_2673, vdims_2674, target_2, target_3, target_4)
and not func_1(vndims_2673, vdims_2674, vlbs_2675, target_2, target_6, target_7, target_8)
and func_2(target_2)
and func_3(vndims_2673, target_3)
and func_4(vdims_2674, target_4)
and func_6(vndims_2673, vdims_2674, target_6)
and func_7(vlbs_2675, target_7)
and func_8(vndims_2673, vlbs_2675, target_8)
and vndims_2673.getType().hasName("int")
and vdims_2674.getType().hasName("int[6]")
and vlbs_2675.getType().hasName("int[6]")
and vndims_2673.(LocalVariable).getFunction() = func
and vdims_2674.(LocalVariable).getFunction() = func
and vlbs_2675.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
