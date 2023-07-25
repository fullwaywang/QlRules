/**
 * @name wavpack-6f8bb34c2993a48ab9afbe353e6d0cff7c8d821d-ParseDsdiffHeaderConfig
 * @id cpp/wavpack/6f8bb34c2993a48ab9afbe353e6d0cff7c8d821d/ParseDsdiffHeaderConfig
 * @description wavpack-6f8bb34c2993a48ab9afbe353e6d0cff7c8d821d-cli/dsdiff.c-ParseDsdiffHeaderConfig CVE-2018-10538
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbytes_to_copy_281, Parameter vinfilename_80, NotExpr target_4, FunctionCall target_2, LogicalOrExpr target_5, ExprStmt target_6, ExprStmt target_7) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbytes_to_copy_281
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbytes_to_copy_281
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4194304"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s is not a valid .DFF file!"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinfilename_80
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_2.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vbuff_282, NotExpr target_4, LogicalOrExpr target_5) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuff_282
		and target_1.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(3)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(Variable vbytes_to_copy_281, FunctionCall target_2) {
		target_2.getTarget().hasName("malloc")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vbytes_to_copy_281
}

predicate func_3(Function func, Initializer target_3) {
		target_3.getExpr() instanceof FunctionCall
		and target_3.getExpr().getEnclosingFunction() = func
}

predicate func_4(NotExpr target_4) {
		target_4.getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_4.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="ckID"
		and target_4.getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="DSD "
		and target_4.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
}

predicate func_5(Variable vbytes_to_copy_281, Variable vbuff_282, LogicalOrExpr target_5) {
		target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("DoReadFile")
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuff_282
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbytes_to_copy_281
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbytes_to_copy_281
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="qmode"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="512"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("WavpackAddWrapper")
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuff_282
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbytes_to_copy_281
}

predicate func_6(Parameter vinfilename_80, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_6.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s is not a valid .DFF file!"
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinfilename_80
}

predicate func_7(Parameter vinfilename_80, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_7.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s: %s"
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinfilename_80
		and target_7.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("WavpackGetErrorMessage")
}

from Function func, Variable vbytes_to_copy_281, Variable vbuff_282, Parameter vinfilename_80, FunctionCall target_2, Initializer target_3, NotExpr target_4, LogicalOrExpr target_5, ExprStmt target_6, ExprStmt target_7
where
not func_0(vbytes_to_copy_281, vinfilename_80, target_4, target_2, target_5, target_6, target_7)
and not func_1(vbuff_282, target_4, target_5)
and func_2(vbytes_to_copy_281, target_2)
and func_3(func, target_3)
and func_4(target_4)
and func_5(vbytes_to_copy_281, vbuff_282, target_5)
and func_6(vinfilename_80, target_6)
and func_7(vinfilename_80, target_7)
and vbytes_to_copy_281.getType().hasName("int")
and vbuff_282.getType().hasName("char *")
and vinfilename_80.getType().hasName("char *")
and vbytes_to_copy_281.getParentScope+() = func
and vbuff_282.getParentScope+() = func
and vinfilename_80.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
