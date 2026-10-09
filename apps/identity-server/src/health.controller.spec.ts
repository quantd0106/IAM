import type { Server } from 'node:http';
import { Test, TestingModule } from '@nestjs/testing';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import type { INestApplication } from '@nestjs/common';
import { AppModule } from './app.module.js';

describe('Identity Server', () => {
  let app: INestApplication<Server>;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication<INestApplication<Server>>();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('initializes the application module', () => {
    expect(app).toBeDefined();
  });

  it('returns a healthy status', async () => {
    await request(app.getHttpServer())
      .get('/health')
      .expect(200)
      .expect({ status: 'ok' });
  });
});
