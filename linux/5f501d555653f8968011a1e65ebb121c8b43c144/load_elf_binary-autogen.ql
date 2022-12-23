/**
 * @name linux-5f501d555653f8968011a1e65ebb121c8b43c144-load_elf_binary
 * @id cpp/linux/5f501d555653f8968011a1e65ebb121c8b43c144/load_elf_binary
 * @description linux-5f501d555653f8968011a1e65ebb121c8b43c144-load_elf_binary CVE-2017-1000253
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable velf_flags_1035) {
	exists(Literal target_0 |
		target_0.getValue()="16"
		and not target_0.getValue()="1048576"
		and target_0.getParent().(AssignOrExpr).getParent().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=velf_flags_1035)
}

predicate func_1(Variable velf_flags_1035) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=velf_flags_1035
		and target_1.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="1048576"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation)
}

predicate func_2(Variable velf_ex_840, Variable velf_flags_1035, Variable valignment_1038, Variable vinterpreter_825, Variable vload_bias_826, Variable vload_addr_set_827, Variable velf_phdata_829) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof EqualityOperation
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vinterpreter_825
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vload_bias_826
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(FunctionCall).getTarget().hasName("mmap_is_ia32")
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="4194304"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(MulExpr).getLeftOperand().(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(MulExpr).getLeftOperand().(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="47"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(MulExpr).getLeftOperand().(DivExpr).getLeftOperand().(SubExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(MulExpr).getLeftOperand().(DivExpr).getLeftOperand().(SubExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(MulExpr).getLeftOperand().(DivExpr).getRightOperand().(Literal).getValue()="3"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("get_current")
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4194304"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vload_bias_826
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("arch_mmap_rnd")
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=valignment_1038
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("maximum_alignment")
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=velf_phdata_829
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="e_phnum"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velf_ex_840
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(VariableAccess).getTarget()=valignment_1038
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAndExpr).getLValue().(VariableAccess).getTarget()=vload_bias_826
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=valignment_1038
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=velf_flags_1035
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="1048576"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vload_bias_826
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_2.getParent().(IfStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vload_addr_set_827)
}

predicate func_3(Variable vload_addr_set_827) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vload_addr_set_827
		and target_3.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(1) instanceof IfStmt)
}

predicate func_4(Variable velf_ex_840, Variable velf_flags_1035, Variable vload_addr_set_827) {
	exists(EqualityOperation target_4 |
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="e_type"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velf_ex_840
		and target_4.getAnOperand().(Literal).getValue()="2"
		and target_4.getParent().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=vload_addr_set_827
		and target_4.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=velf_flags_1035
		and target_4.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="16")
}

predicate func_6(Variable velf_ex_840, Variable vvaddr_1036, Variable vload_bias_826) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vload_bias_826
		and target_6.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vload_bias_826
		and target_6.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vvaddr_1036
		and target_6.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getValue()="18446744073709547520"
		and target_6.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_6.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_6.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="e_type"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velf_ex_840
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="3")
}

predicate func_7(Variable velf_ex_840, Variable vtotal_size_1037, Variable velf_phdata_829) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtotal_size_1037
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("total_mapping_size")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=velf_phdata_829
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="e_phnum"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velf_ex_840
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="e_type"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velf_ex_840
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="3")
}

predicate func_8(Variable vretval_833, Variable velf_ex_840, Variable vtotal_size_1037) {
	exists(IfStmt target_8 |
		target_8.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vtotal_size_1037
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretval_833
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_8.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="e_type"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=velf_ex_840
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="3")
}

predicate func_10(Variable velf_flags_1035, Variable vload_addr_set_827) {
	exists(LogicalOrExpr target_10 |
		target_10.getAnOperand() instanceof EqualityOperation
		and target_10.getAnOperand().(VariableAccess).getTarget()=vload_addr_set_827
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=velf_flags_1035
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="16")
}

from Function func, Variable vretval_833, Variable velf_ex_840, Variable velf_flags_1035, Variable vvaddr_1036, Variable vtotal_size_1037, Variable valignment_1038, Variable vinterpreter_825, Variable vload_bias_826, Variable vload_addr_set_827, Variable velf_phdata_829
where
func_0(velf_flags_1035)
and not func_1(velf_flags_1035)
and not func_2(velf_ex_840, velf_flags_1035, valignment_1038, vinterpreter_825, vload_bias_826, vload_addr_set_827, velf_phdata_829)
and not func_3(vload_addr_set_827)
and func_4(velf_ex_840, velf_flags_1035, vload_addr_set_827)
and func_6(velf_ex_840, vvaddr_1036, vload_bias_826)
and func_7(velf_ex_840, vtotal_size_1037, velf_phdata_829)
and func_8(vretval_833, velf_ex_840, vtotal_size_1037)
and func_10(velf_flags_1035, vload_addr_set_827)
and vretval_833.getType().hasName("int")
and velf_ex_840.getType().hasName("elf64_hdr *")
and velf_flags_1035.getType().hasName("int")
and vvaddr_1036.getType().hasName("unsigned long")
and vtotal_size_1037.getType().hasName("unsigned long")
and valignment_1038.getType().hasName("unsigned long")
and vinterpreter_825.getType().hasName("file *")
and vload_bias_826.getType().hasName("unsigned long")
and vload_addr_set_827.getType().hasName("int")
and velf_phdata_829.getType().hasName("elf64_phdr *")
and vretval_833.getParentScope+() = func
and velf_ex_840.getParentScope+() = func
and velf_flags_1035.getParentScope+() = func
and vvaddr_1036.getParentScope+() = func
and vtotal_size_1037.getParentScope+() = func
and valignment_1038.getParentScope+() = func
and vinterpreter_825.getParentScope+() = func
and vload_bias_826.getParentScope+() = func
and vload_addr_set_827.getParentScope+() = func
and velf_phdata_829.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
