/**
 * @name wavpack-f68a9555b548306c5b1ee45199ccdc4a16a6101b-ParseCaffHeaderConfig
 * @id cpp/wavpack/f68a9555b548306c5b1ee45199ccdc4a16a6101b/ParseCaffHeaderConfig
 * @description wavpack-f68a9555b548306c5b1ee45199ccdc4a16a6101b-cli/caff.c-ParseCaffHeaderConfig CVE-2019-1010317
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(NotExpr target_4, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("uint32_t")
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vbcount_155, BlockStmt target_5) {
	exists(LogicalOrExpr target_2 |
		target_2.getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("uint32_t")
		and target_2.getAnOperand() instanceof NotExpr
		and target_2.getParent().(LogicalOrExpr).getAnOperand() instanceof NotExpr
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbcount_155
		and target_2.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getValue()="4"
		and target_2.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_5)
}

predicate func_3(Variable vbcount_155, Variable vmEditCount_459, Parameter vinfile_153, BlockStmt target_5, NotExpr target_3) {
		target_3.getOperand().(FunctionCall).getTarget().hasName("DoReadFile")
		and target_3.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinfile_153
		and target_3.getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmEditCount_459
		and target_3.getOperand().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="4"
		and target_3.getOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbcount_155
		and target_3.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbcount_155
		and target_3.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(SizeofExprOperator).getValue()="4"
		and target_3.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_4(NotExpr target_4) {
		target_4.getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_4.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="mChunkType"
		and target_4.getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="desc"
		and target_4.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
}

predicate func_5(BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s is not a valid .CAF file!"
		and target_5.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
}

from Function func, Variable vbcount_155, Variable vmEditCount_459, Parameter vinfile_153, NotExpr target_3, NotExpr target_4, BlockStmt target_5
where
not func_1(target_4, func)
and not func_2(vbcount_155, target_5)
and func_3(vbcount_155, vmEditCount_459, vinfile_153, target_5, target_3)
and func_4(target_4)
and func_5(target_5)
and vbcount_155.getType().hasName("uint32_t")
and vmEditCount_459.getType().hasName("uint32_t")
and vinfile_153.getType().hasName("FILE *")
and vbcount_155.getParentScope+() = func
and vmEditCount_459.getParentScope+() = func
and vinfile_153.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
