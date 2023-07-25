/**
 * @name capstone-87a25bb543c8e4c09b48d4b4a6c7db31ce58df06-X86_insn_reg_intel
 * @id cpp/capstone/87a25bb543c8e4c09b48d4b4a6c7db31ce58df06/X86-insn-reg-intel
 * @description capstone-87a25bb543c8e4c09b48d4b4a6c7db31ce58df06-arch/X86/X86Mapping.c-X86_insn_reg_intel CVE-2016-7151
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinsn_regs_intel, ExprStmt target_7, VariableAccess target_0) {
		target_0.getTarget()=vinsn_regs_intel
		and target_0.getParent().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_1(Function func, Initializer target_1) {
		target_1.getExpr().(DivExpr).getValue()="57"
		and target_1.getExpr().getEnclosingFunction() = func
}

predicate func_2(Variable vinsn_regs_intel, ArrayExpr target_8, VariableAccess target_2) {
		target_2.getTarget()=vinsn_regs_intel
		and target_8.getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getLocation())
}

predicate func_3(Function func, Literal target_3) {
		target_3.getValue()="2"
		and not target_3.getValue()="0"
		and target_3.getParent().(DivExpr).getParent().(Initializer).getExpr().(DivExpr).getValue()="57"
		and target_3.getEnclosingFunction() = func
}

predicate func_5(Variable vlast_2940, Parameter vid_2937, RelationalOperation target_9, RelationalOperation target_10, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="insn"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("insn_reg[115]")
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vid_2937
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="insn"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("insn_reg[115]")
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlast_2940
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vid_2937
		and target_5.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_5)
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_9.getGreaterOperand().(VariableAccess).getLocation())
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_10.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_6(Function func, DivExpr target_6) {
		target_6.getValue()="115"
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Variable vinsn_regs_intel, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinsn_regs_intel
		and target_7.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="1380"
}

predicate func_8(Variable vinsn_regs_intel, ArrayExpr target_8) {
		target_8.getArrayBase().(VariableAccess).getTarget()=vinsn_regs_intel
		and target_8.getArrayOffset().(Literal).getValue()="0"
}

predicate func_9(Variable vlast_2940, RelationalOperation target_9) {
		 (target_9 instanceof GEExpr or target_9 instanceof LEExpr)
		and target_9.getGreaterOperand().(VariableAccess).getTarget()=vlast_2940
}

predicate func_10(Parameter vid_2937, RelationalOperation target_10) {
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getLesserOperand().(ValueFieldAccess).getTarget().getName()="insn"
		and target_10.getGreaterOperand().(VariableAccess).getTarget()=vid_2937
}

from Function func, Variable vlast_2940, Variable vinsn_regs_intel, Parameter vid_2937, VariableAccess target_0, Initializer target_1, VariableAccess target_2, Literal target_3, DivExpr target_6, ExprStmt target_7, ArrayExpr target_8, RelationalOperation target_9, RelationalOperation target_10
where
func_0(vinsn_regs_intel, target_7, target_0)
and func_1(func, target_1)
and func_2(vinsn_regs_intel, target_8, target_2)
and func_3(func, target_3)
and not func_5(vlast_2940, vid_2937, target_9, target_10, func)
and func_6(func, target_6)
and func_7(vinsn_regs_intel, target_7)
and func_8(vinsn_regs_intel, target_8)
and func_9(vlast_2940, target_9)
and func_10(vid_2937, target_10)
and vlast_2940.getType().hasName("unsigned int")
and vinsn_regs_intel.getType() instanceof ArrayType
and vid_2937.getType().hasName("unsigned int")
and vlast_2940.getParentScope+() = func
and not vinsn_regs_intel.getParentScope+() = func
and vid_2937.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
