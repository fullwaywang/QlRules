/**
 * @name linux-27ae357fa82be5ab73b2ef8d39dcb8ca2563483a-__oom_reap_task_mm
 * @id cpp/linux/27ae357fa82be5ab73b2ef8d39dcb8ca2563483a/__oom_reap_task_mm
 * @description linux-27ae357fa82be5ab73b2ef8d39dcb8ca2563483a-__oom_reap_task_mm CVE-2018-1000200
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof Struct
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

predicate func_1(Parameter vmm_483) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmm_483
		and target_1.getParent().(FunctionCall).getParent().(ConditionalExpr).getThen() instanceof FunctionCall)
}

predicate func_3(Variable vvma_486) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="vm_start"
		and target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_486
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("vma_is_anonymous")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_486
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_486
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8")
}

predicate func_4(Variable vvma_486) {
	exists(DeclStmt target_4 |
		target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="vm_end"
		and target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_486
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("vma_is_anonymous")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_486
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_486
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8")
}

predicate func_5(Parameter vmm_483, Variable vtlb_485, Variable vvma_486, Variable vstart_560, Variable vend_561) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("tlb_gather_mmu")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtlb_485
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmm_483
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vstart_560
		and target_5.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vend_561
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("vma_is_anonymous")
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_486
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_486
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8")
}

predicate func_6(Parameter vmm_483, Variable vvma_486, Variable vstart_560, Variable vend_561) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("mmu_notifier_invalidate_range_start")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmm_483
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstart_560
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vend_561
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("vma_is_anonymous")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_486
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_486
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8")
}

predicate func_7(Variable vtlb_485, Variable vvma_486, Variable vstart_560, Variable vend_561) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("unmap_page_range")
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtlb_485
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvma_486
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vstart_560
		and target_7.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vend_561
		and target_7.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("vma_is_anonymous")
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_486
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_486
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8")
}

predicate func_8(Parameter vmm_483, Variable vvma_486, Variable vstart_560, Variable vend_561) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("mmu_notifier_invalidate_range_end")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmm_483
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstart_560
		and target_8.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vend_561
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("vma_is_anonymous")
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_486
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_486
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8")
}

predicate func_9(Variable vtlb_485, Variable vvma_486, Variable vstart_560, Variable vend_561) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(FunctionCall).getTarget().hasName("tlb_finish_mmu")
		and target_9.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtlb_485
		and target_9.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstart_560
		and target_9.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vend_561
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("vma_is_anonymous")
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_486
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_486
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8")
}

predicate func_10(Function func) {
	exists(DeclStmt target_10 |
		func.getEntryPoint().(BlockStmt).getAStmt()=target_10)
}

predicate func_11(Variable voom_lock, Function func) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(FunctionCall).getTarget().hasName("mutex_lock_nested")
		and target_11.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=voom_lock
		and target_11.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11)
}

predicate func_12(Parameter vmm_483, Variable vret_487, Parameter vtsk_483, Function func) {
	exists(IfStmt target_12 |
		target_12.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("down_read_trylock")
		and target_12.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="mmap_sem"
		and target_12.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmm_483
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_487
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("trace_skip_task_reaping")
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pid"
		and target_12.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtsk_483
		and target_12.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12)
}

predicate func_17(Parameter vmm_483) {
	exists(ExprStmt target_17 |
		target_17.getExpr().(FunctionCall).getTarget().hasName("up_read")
		and target_17.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="mmap_sem"
		and target_17.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmm_483
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("mm_has_blockable_invalidate_notifiers")
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmm_483)
}

predicate func_18(Parameter vmm_483) {
	exists(ExprStmt target_18 |
		target_18.getExpr().(FunctionCall).getTarget().hasName("schedule_timeout_idle")
		and target_18.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="250"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("mm_has_blockable_invalidate_notifiers")
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmm_483)
}

predicate func_20(Parameter vmm_483, Parameter vtsk_483, Function func) {
	exists(IfStmt target_20 |
		target_20.getCondition().(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_20.getCondition().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("constant_test_bit")
		and target_20.getCondition().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(Literal).getValue()="21"
		and target_20.getCondition().(ConditionalExpr).getThen().(FunctionCall).getArgument(1) instanceof AddressOfExpr
		and target_20.getCondition().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("variable_test_bit")
		and target_20.getCondition().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(Literal).getValue()="21"
		and target_20.getCondition().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_20.getCondition().(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmm_483
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("up_read")
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="mmap_sem"
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmm_483
		and target_20.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("trace_skip_task_reaping")
		and target_20.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pid"
		and target_20.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtsk_483
		and target_20.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_20)
}

predicate func_24(Parameter vtsk_483, Function func) {
	exists(ExprStmt target_24 |
		target_24.getExpr().(FunctionCall).getTarget().hasName("trace_start_task_reaping")
		and target_24.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pid"
		and target_24.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtsk_483
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_24)
}

predicate func_25(Function func) {
	exists(IfStmt target_25 |
		target_25.getCondition() instanceof LogicalOrExpr
		and target_25.getThen().(BlockStmt).getStmt(0) instanceof DeclStmt
		and target_25.getThen().(BlockStmt).getStmt(1) instanceof DeclStmt
		and target_25.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_25.getThen().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_25.getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_25.getThen().(BlockStmt).getStmt(5) instanceof ExprStmt
		and target_25.getThen().(BlockStmt).getStmt(6) instanceof ExprStmt
		and target_25.getEnclosingFunction() = func)
}

predicate func_26(Parameter vmm_483, Parameter vtsk_483, Function func) {
	exists(ExprStmt target_26 |
		target_26.getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_26.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="6oom_reaper: reaped process %d (%s), now anon-rss:%lukB, file-rss:%lukB, shmem-rss:%lukB\n"
		and target_26.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("task_pid_nr")
		and target_26.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtsk_483
		and target_26.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="comm"
		and target_26.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtsk_483
		and target_26.getExpr().(FunctionCall).getArgument(3).(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getTarget().hasName("get_mm_counter")
		and target_26.getExpr().(FunctionCall).getArgument(3).(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmm_483
		and target_26.getExpr().(FunctionCall).getArgument(3).(BinaryBitwiseOperation).getRightOperand().(SubExpr).getValue()="2"
		and target_26.getExpr().(FunctionCall).getArgument(3).(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(Literal).getValue()="12"
		and target_26.getExpr().(FunctionCall).getArgument(3).(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="10"
		and target_26.getExpr().(FunctionCall).getArgument(4).(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getTarget().hasName("get_mm_counter")
		and target_26.getExpr().(FunctionCall).getArgument(4).(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmm_483
		and target_26.getExpr().(FunctionCall).getArgument(4).(BinaryBitwiseOperation).getRightOperand().(SubExpr).getValue()="2"
		and target_26.getExpr().(FunctionCall).getArgument(4).(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(Literal).getValue()="12"
		and target_26.getExpr().(FunctionCall).getArgument(4).(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="10"
		and target_26.getExpr().(FunctionCall).getArgument(5).(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getTarget().hasName("get_mm_counter")
		and target_26.getExpr().(FunctionCall).getArgument(5).(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmm_483
		and target_26.getExpr().(FunctionCall).getArgument(5).(BinaryBitwiseOperation).getRightOperand().(SubExpr).getValue()="2"
		and target_26.getExpr().(FunctionCall).getArgument(5).(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(Literal).getValue()="12"
		and target_26.getExpr().(FunctionCall).getArgument(5).(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="10"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_26)
}

predicate func_28(Parameter vtsk_483, Function func) {
	exists(ExprStmt target_28 |
		target_28.getExpr().(FunctionCall).getTarget().hasName("trace_finish_task_reaping")
		and target_28.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pid"
		and target_28.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtsk_483
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_28)
}

predicate func_29(Function func) {
	exists(LabelStmt target_29 |
		target_29.toString() = "label ...:"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_29)
}

predicate func_30(Variable voom_lock, Function func) {
	exists(ExprStmt target_30 |
		target_30.getExpr().(FunctionCall).getTarget().hasName("mutex_unlock")
		and target_30.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=voom_lock
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_30)
}

predicate func_31(Variable vret_487) {
	exists(VariableAccess target_31 |
		target_31.getTarget()=vret_487)
}

from Function func, Parameter vmm_483, Variable vtlb_485, Variable vvma_486, Variable vret_487, Variable voom_lock, Variable vstart_560, Variable vend_561, Parameter vtsk_483
where
func_0(func)
and func_1(vmm_483)
and func_3(vvma_486)
and func_4(vvma_486)
and func_5(vmm_483, vtlb_485, vvma_486, vstart_560, vend_561)
and func_6(vmm_483, vvma_486, vstart_560, vend_561)
and func_7(vtlb_485, vvma_486, vstart_560, vend_561)
and func_8(vmm_483, vvma_486, vstart_560, vend_561)
and func_9(vtlb_485, vvma_486, vstart_560, vend_561)
and func_10(func)
and func_11(voom_lock, func)
and func_12(vmm_483, vret_487, vtsk_483, func)
and func_17(vmm_483)
and func_18(vmm_483)
and func_20(vmm_483, vtsk_483, func)
and func_24(vtsk_483, func)
and func_25(func)
and func_26(vmm_483, vtsk_483, func)
and func_28(vtsk_483, func)
and func_29(func)
and func_30(voom_lock, func)
and func_31(vret_487)
and vmm_483.getType().hasName("mm_struct *")
and vtlb_485.getType().hasName("mmu_gather")
and vvma_486.getType().hasName("vm_area_struct *")
and vret_487.getType().hasName("bool")
and voom_lock.getType().hasName("mutex")
and vstart_560.getType().hasName("const unsigned long")
and vend_561.getType().hasName("const unsigned long")
and vtsk_483.getType().hasName("task_struct *")
and vmm_483.getParentScope+() = func
and vtlb_485.getParentScope+() = func
and vvma_486.getParentScope+() = func
and vret_487.getParentScope+() = func
and not voom_lock.getParentScope+() = func
and vstart_560.getParentScope+() = func
and vend_561.getParentScope+() = func
and vtsk_483.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
