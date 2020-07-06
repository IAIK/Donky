  /* MAGIC SECTIONS */
  /*
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  .test1 :
  {
     _test1_start = .;
      *test1.o(*)
     _test1_end = .;
  }
  */
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  .pk_d :
  {
      __start_pk_all = .;
      __start_pk_data = .;
      __start_pk_key = .;
      *(.pk_key)
      __stop_pk_key = .;
      *(.pk_data)
      /**(.dynbss)
      *(.bss .bss.* .gnu.linkonce.b.*)
      *(COMMON)*/

      . = ALIGN(CONSTANT (MAXPAGESIZE));
      __stop_pk_data = .;
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  .pk_t :
  {
      __start_pk_code = .;
      __start_pk_utvec_table = .;
      *(.pk_utvec_table)
      __stop_pk_utvec_table = .;
      *(.pk)
      /* *(*) TODO: Currently all non-pk tagged symbols are in unprotected section (caught by the arch-specific linker script) */
      . = ALIGN(CONSTANT (MAXPAGESIZE));
      __stop_pk_code = .;
      __stop_pk_all = .;
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _test2_start = .;
  .test2t :
  {
      *test2.o(.text)
      /* *test2_ecall.S(*) */
  }
  /* . = ALIGN(CONSTANT (MAXPAGESIZE));*/
  .test2d :
  {
      *test2.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _test2_end = .;


  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _test3_start = .;
  _test3t_start = .;
  .test3t :
  {
      *test3.o(.text)
      /* *test3_ecall.S(*) */
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _test3t_end = .;
  _test3d_start = .;
  .test3d :
  {
      *test3.o(*)
  }
  . = ALIGN(CONSTANT (MAXPAGESIZE));
  _test3d_end = .;
  _test3_end = .;

  /* MAGIC SECTIONS END */
